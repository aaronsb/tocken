// Code panel state machine (issue #3). States:
//   AWAITING_TOUCH → UNLOCKED_HIDDEN | TOUCH_TIMEOUT | ERROR
// Owns the tray-click activation handshake (window:shown listener),
// the YubiKey unlock dance, code list rendering with auto-refresh on
// rotation boundaries, and the pivot to the enrollment panel.

import { initEnrollPanel } from "./enroll.js";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

export async function initCodePanel(root) {
  const panes = {
    awaiting: root.querySelector('[data-state="awaiting-touch"]'),
    unlocked: root.querySelector('[data-state="unlocked"]'),
    timeout: root.querySelector('[data-state="touch-timeout"]'),
    error: root.querySelector('[data-state="error"]'),
  };
  const list = root.querySelector("#code-list");
  const empty = root.querySelector("#code-empty");
  const errBody = root.querySelector("#code-error");
  const retry = root.querySelector("#retry-unlock");
  const errorRetry = root.querySelector("#error-retry");
  const dismiss = root.querySelector("#dismiss");
  const quitBtn = root.querySelector("#quit-btn");
  const revealBtn = root.querySelector("#reveal-toggle");
  const subtitle = root.querySelector("#main-subtitle");
  const toast = document.querySelector("#code-toast");
  const addBtn = root.querySelector("#add-account");
  const emptyAddBtn = root.querySelector("#empty-add-account");
  const enrollPanel = document.querySelector("#enroll");

  let revealed = false;
  let refreshTimer = null;
  let toastTimer = null;
  let currentState = null;
  // Guards re-entry of enterAwaiting from the three call sites
  // (window:shown, retry buttons, startup get_codes-Locked path).
  // Without it, a rapid re-activation could double-fire unlock and
  // produce stacked LED-blink windows. Backend's generation counter
  // is the deeper safety net; this is the cheap UX guard.
  let unlockInFlight = false;

  const showPane = (key) => {
    Object.entries(panes).forEach(([k, el]) =>
      el.classList.toggle("hidden", k !== key)
    );
    currentState = key;
  };

  const formatCode = (s) => {
    if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
    if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
    return s;
  };

  const flashToast = (msg) => {
    toast.textContent = msg;
    toast.classList.add("visible");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("visible"), 1500);
  };

  const copyCode = async (li, code) => {
    try {
      await navigator.clipboard.writeText(code);
      li.classList.add("flash");
      flashToast("Copied");
      setTimeout(() => li.classList.remove("flash"), 400);
    } catch (err) {
      flashToast("Copy failed");
      console.error("clipboard.writeText:", err);
    }
  };

  const renderCodes = (codes) => {
    list.innerHTML = "";
    empty.classList.toggle("hidden", codes.length > 0);
    addBtn.classList.toggle("hidden", codes.length === 0);
    for (const c of codes) {
      const li = document.createElement("li");
      li.dataset.id = c.id;

      const labelDiv = document.createElement("div");
      labelDiv.className = "label";
      const issuer = document.createElement("span");
      issuer.className = "issuer";
      issuer.textContent = c.issuer;
      const account = document.createElement("span");
      account.className = "account";
      account.textContent = c.account;
      labelDiv.append(issuer, account);

      const digits = document.createElement("span");
      digits.className = "digits";
      digits.dataset.code = c.code;
      digits.textContent = revealed ? formatCode(c.code) : "••• •••";

      const countdown = document.createElement("div");
      countdown.className = "countdown";
      const fill = document.createElement("div");
      fill.style.width = `${(c.time_remaining / c.period) * 100}%`;
      countdown.appendChild(fill);

      li.append(labelDiv, digits, countdown);
      li.addEventListener("click", () => copyCode(li, c.code));
      list.appendChild(li);
    }
  };

  const refreshCodes = async () => {
    let response;
    try {
      response = await invoke("get_codes");
    } catch (err) {
      errBody.textContent = String(err);
      showPane("error");
      return;
    }

    if (response.kind === "Locked") {
      // Backend re-locked. Restart the unlock flow.
      enterAwaiting();
      return;
    }

    renderCodes(response.codes);

    // Re-fetch just past the next rollover. Pick the shortest
    // time_remaining among entries — that's when a code changes.
    // 200ms buffer to land safely after the period boundary.
    if (response.codes.length === 0) {
      // Empty store. Nothing to refresh on a period boundary; the
      // backend's re-lock check still fires on its own when the user
      // dismisses or the threshold is crossed via a future fetch.
      // Don't schedule — Math.min(...[]) is Infinity and setTimeout
      // would tight-loop.
      return;
    }
    const minRemaining = Math.min(
      ...response.codes.map((c) => c.time_remaining)
    );
    const ms = (minRemaining > 0 ? minRemaining : 1) * 1000 + 200;
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(refreshCodes, ms);
  };

  const enterAwaiting = async () => {
    if (unlockInFlight) return;
    unlockInFlight = true;
    try {
      if (refreshTimer) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
      }
      revealed = false;
      revealBtn.classList.add("hidden");
      subtitle.textContent = "locked";
      showPane("awaiting");

      // Order: dialog state first, then YubiKey input. Without this,
      // the unlock invoke can fire before the browser has painted the
      // awaiting pane, so the LED starts blinking with no visible UI
      // confirmation of what's about to happen. Two rAFs guarantee
      // the pane has committed; an additional ~150ms gives the user
      // a beat to register the pulsing "Waiting for YubiKey touch..."
      // banner before the LED comes alive.
      await new Promise((r) =>
        requestAnimationFrame(() => requestAnimationFrame(r))
      );
      await new Promise((r) => setTimeout(r, 150));

      // Per spike #23: age-plugin-yubikey doesn't emit a touch-prompt
      // callback; the LED is the user signal.
      let result;
      try {
        result = await invoke("unlock");
      } catch (err) {
        handleUnlockError(err);
        return;
      }
      enterUnlocked(result.entries);
    } finally {
      unlockInFlight = false;
    }
  };

  const handleUnlockError = (err) => {
    if (err && err.kind === "TouchTimeout") {
      // Same pane covers genuine touch-timeouts and YubiKey-identity
      // mismatches. Retry triggers a fresh unlock; if the mismatch is
      // structural (e.g., slot reprovisioned), the user re-runs the
      // wizard. We don't try to disambiguate further from the IPC.
      showPane("timeout");
      return;
    }
    if (err && err.kind === "PluginMissing") {
      errBody.textContent =
        "age-plugin-yubikey is not installed or not on PATH.";
      showPane("error");
      return;
    }
    if (err && err.kind === "NoIdentity") {
      errBody.textContent =
        "No YubiKey identity is configured. Re-run the first-run wizard.";
      showPane("error");
      return;
    }
    if (err && err.kind === "StoreCorrupted") {
      errBody.textContent =
        "The encrypted store is corrupted. Restore from a backup blob.";
      showPane("error");
      return;
    }
    const detail =
      err && err.detail ? err.detail : err && err.kind ? err.kind : String(err);
    errBody.textContent = detail;
    showPane("error");
  };

  const enterUnlocked = async (_summaries) => {
    subtitle.textContent = "unlocked";
    revealBtn.classList.remove("hidden");
    showPane("unlocked");
    await refreshCodes();
  };

  const enroll = initEnrollPanel(enrollPanel, {
    onCancel: () => {
      enrollPanel.classList.add("hidden");
      root.classList.remove("hidden");
    },
    onAdded: async () => {
      enrollPanel.classList.add("hidden");
      root.classList.remove("hidden");
      flashToast("Account added");
      await refreshCodes();
    },
  });

  const showEnroll = () => {
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    root.classList.add("hidden");
    enrollPanel.classList.remove("hidden");
    enroll.reset();
  };

  // Wire interactions
  retry.addEventListener("click", () => enterAwaiting());
  errorRetry.addEventListener("click", () => enterAwaiting());
  addBtn.addEventListener("click", showEnroll);
  emptyAddBtn.addEventListener("click", showEnroll);

  dismiss.addEventListener("click", async () => {
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    // Drops the session and hides the window. JS state resets on the
    // next tray click via window:shown.
    try {
      await invoke("hide_window");
    } catch (err) {
      console.error("hide_window:", err);
    }
  });

  quitBtn.addEventListener("click", async () => {
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    try {
      await invoke("quit_app");
    } catch (err) {
      console.error("quit_app:", err);
    }
  });

  revealBtn.addEventListener("click", () => {
    revealed = !revealed;
    revealBtn.textContent = revealed ? "hide" : "eye";
    list.querySelectorAll(".digits").forEach((el) => {
      el.textContent = revealed ? formatCode(el.dataset.code) : "••• •••";
    });
  });

  // Backend emits "window:shown" when the user clicks the tray icon.
  // Awaited so the IPC subscription is in place before the visibility
  // check below: without await, listen() returns a Promise and the
  // subscription lands asynchronously — an Activate that fires during
  // that gap drops the event and the panel never enters awaiting.
  // initCodePanel runs once per page load (re-init only happens via
  // window.location.reload, which discards the JS context), so the
  // unlistener is held to the page's lifetime by design.
  await listen("window:shown", () => {
    enterAwaiting();
  });

  // Two startup paths land here:
  //   - Cold launch: window is hidden (tauri.conf: visible=false).
  //     Wait for window:shown.
  //   - Post-wizard reload: window is already visible (the user
  //     completed the wizard, which did its own verification unlock).
  //     The backend session is already unlocked, so try get_codes
  //     first — if it returns Codes, render directly without
  //     prompting for another touch. Only fall back to enterAwaiting
  //     if the backend says the session is Locked.
  const win = window.__TAURI__.window.getCurrentWindow();
  const visible = await win.isVisible();
  if (!visible) return;
  try {
    const response = await invoke("get_codes");
    if (response.kind === "Codes") {
      subtitle.textContent = "unlocked";
      revealBtn.classList.remove("hidden");
      showPane("unlocked");
      renderCodes(response.codes);
      if (response.codes.length > 0) {
        const minRemaining = Math.min(
          ...response.codes.map((c) => c.time_remaining)
        );
        const ms = (minRemaining > 0 ? minRemaining : 1) * 1000 + 200;
        refreshTimer = setTimeout(refreshCodes, ms);
      }
      return;
    }
  } catch (err) {
    console.error("startup get_codes:", err);
  }
  enterAwaiting();
}
