const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const WIZARD_STEPS = ["welcome", "passphrase", "confirm", "yubikey", "location", "done"];

window.addEventListener("DOMContentLoaded", async () => {
  const mainPanel = document.querySelector("#main-panel");
  const wizard = document.querySelector("#wizard");

  try {
    const initialized = await invoke("is_initialized");
    if (initialized) {
      mainPanel.classList.remove("hidden");
      initCodePanel(mainPanel);
    } else {
      wizard.classList.remove("hidden");
      initWizard(wizard);
    }
  } catch (err) {
    console.error("is_initialized failed:", err);
    mainPanel.classList.remove("hidden");
    initCodePanel(mainPanel);
  }

  // Custom right-click menu (native menus close the popup on focus).
  // Copy uses the current selection; Select all targets the visible
  // wizard pane or the code panel's status line — codes themselves
  // are user-select: none.
  const ctxMenu = document.querySelector("#ctx-menu");
  const ctxCopy = document.querySelector("#ctx-copy");
  const ctxSelectAll = document.querySelector("#ctx-select-all");
  const hideCtx = () => ctxMenu.classList.remove("visible");

  document.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const margin = 4;
    const x = Math.min(e.clientX, window.innerWidth - ctxMenu.offsetWidth - margin);
    const y = Math.min(e.clientY, window.innerHeight - ctxMenu.offsetHeight - margin);
    ctxMenu.style.left = `${x}px`;
    ctxMenu.style.top = `${y}px`;
    ctxMenu.classList.add("visible");
  });

  document.addEventListener("click", (e) => {
    if (!ctxMenu.contains(e.target)) hideCtx();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideCtx();
  });

  ctxCopy.addEventListener("click", async () => {
    const text = window.getSelection().toString();
    if (text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback for environments without clipboard API.
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
    }
    hideCtx();
  });

  ctxSelectAll.addEventListener("click", () => {
    const visiblePane =
      document.querySelector(".wizard-pane:not(.hidden)") ||
      document.querySelector(".code-pane:not(.hidden)");
    if (visiblePane) {
      const range = document.createRange();
      range.selectNodeContents(visiblePane);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
    hideCtx();
  });
});

// ─────────────────────────────────────────────────────────────────────
// Wizard state machine (issue #5)
// ─────────────────────────────────────────────────────────────────────

function initWizard(root) {
  const stepLabel = root.querySelector("#wizard-step-label");
  const panes = Array.from(root.querySelectorAll(".wizard-pane"));
  const paneByStep = Object.fromEntries(panes.map((p) => [p.dataset.step, p]));

  const ctx = {
    passphrase: null,
    yubikeyRecipient: null,
    pinPukMessage: null,
  };

  let index = 0;
  const showStep = async (i) => {
    panes.forEach((p, j) => p.classList.toggle("hidden", i !== j));
    stepLabel.textContent = WIZARD_STEPS[i] ?? "";
    index = i;
    const step = WIZARD_STEPS[i];
    const enter = stepHandlers[step];
    if (enter) await enter(paneByStep[step], ctx);
  };

  const advance = () => index < panes.length - 1 && showStep(index + 1);

  root.addEventListener("click", (e) => {
    const next = e.target.closest("[data-next]");
    if (!next || next.disabled) return;
    advance();
  });

  const stepHandlers = {
    welcome: () => {},

    passphrase: async (pane) => {
      const display = pane.querySelector("#wizard-passphrase");
      const regen = pane.querySelector("#wizard-regen");
      const refresh = async () => {
        ctx.passphrase = await invoke("generate_passphrase");
        display.textContent = ctx.passphrase;
      };
      if (!regen.dataset.bound) {
        regen.dataset.bound = "1";
        regen.addEventListener("click", refresh);
      }
      await refresh();
    },

    confirm: (pane) => {
      const input = pane.querySelector("#wizard-confirm-input");
      const next = pane.querySelector("[data-next]");
      const PHRASE = "I have written it down";
      input.value = "";
      next.disabled = true;
      if (!input.dataset.bound) {
        input.dataset.bound = "1";
        input.addEventListener("input", () => {
          next.disabled = input.value.trim() !== PHRASE;
        });
      }
      input.focus();
    },

    yubikey: async (pane) => {
      const status = pane.querySelector("#wizard-yk-status");
      const provisionBtn = pane.querySelector("#wizard-yk-provision");
      const output = pane.querySelector("#wizard-yk-output");
      const next = pane.querySelector("[data-next]");

      provisionBtn.classList.add("hidden");
      output.classList.add("hidden");
      output.textContent = "";
      next.classList.add("hidden");
      status.textContent = "Detecting…";

      let detect;
      try {
        detect = await invoke("detect_yubikey");
      } catch (err) {
        status.textContent = `Detection failed: ${err}`;
        return;
      }

      if (detect.configured && detect.recipient) {
        ctx.yubikeyRecipient = detect.recipient;
        const serial = detect.serial ? ` (serial ${detect.serial})` : "";
        status.textContent = `Existing YubiKey identity detected${serial}.`;
        next.classList.remove("hidden");
        return;
      }

      status.textContent =
        "No age identity on this YubiKey yet. Plug it in and click Provision. You'll be asked to touch the key.";
      provisionBtn.classList.remove("hidden");
      provisionBtn.disabled = false;

      if (provisionBtn.dataset.bound) return;
      provisionBtn.dataset.bound = "1";

      const unlisten = await listen("wizard:provision-output", (event) => {
        output.textContent += `${event.payload}\n`;
        output.scrollTop = output.scrollHeight;
      });

      provisionBtn.addEventListener("click", async () => {
        provisionBtn.disabled = true;
        status.textContent = "Provisioning… touch your YubiKey when it blinks.";
        output.classList.remove("hidden");
        output.textContent = "";
        try {
          const result = await invoke("provision_yubikey");
          ctx.yubikeyRecipient = result.recipient;
          ctx.pinPukMessage = result.pin_puk_message ?? null;
          status.textContent = "YubiKey provisioned.";
          if (ctx.pinPukMessage) {
            output.textContent +=
              `\n${ctx.pinPukMessage}\n\n` +
              "Save the PIN/PUK above offline — needed only for PIV admin operations.";
          }
          next.classList.remove("hidden");
          unlisten();
        } catch (err) {
          status.textContent = `Provisioning failed: ${err}`;
          provisionBtn.disabled = false;
        }
      });
    },

    location: (pane) => {
      const display = pane.querySelector("#wizard-location");
      display.textContent =
        "$XDG_DATA_HOME/tocken/{master.age,store.age}\n" +
        "(typically ~/.local/share/tocken/)";
    },

    done: async (pane) => {
      const finish = pane.querySelector("#wizard-finish");
      finish.disabled = true;
      try {
        const result = await invoke("finalize_init", {
          passphrase: ctx.passphrase,
          yubikeyRecipient: ctx.yubikeyRecipient,
        });
        const summary = pane.querySelector("p");
        summary.textContent = `Created: ${result.store_path}`;
        finish.disabled = false;
      } catch (err) {
        const summary = pane.querySelector("p");
        summary.textContent = `Setup failed: ${err}`;
      }

      if (finish.dataset.bound) return;
      finish.dataset.bound = "1";
      finish.addEventListener("click", () => {
        // Reload re-runs is_initialized: on success it lands on the
        // main panel; on prior finalize_init failure (no store written)
        // it re-enters the wizard from welcome — a clean retry.
        window.location.reload();
      });
    },
  };

  showStep(0);
}

// ─────────────────────────────────────────────────────────────────────
// Code panel state machine (issue #3)
// ─────────────────────────────────────────────────────────────────────

function initCodePanel(root) {
  const panes = {
    awaiting: root.querySelector('[data-state="awaiting-touch"]'),
    unlocked: root.querySelector('[data-state="unlocked"]'),
    timeout: root.querySelector('[data-state="touch-timeout"]'),
    error: root.querySelector('[data-state="error"]'),
  };
  const list = root.querySelector("#code-list");
  const errBody = root.querySelector("#code-error");
  const retry = root.querySelector("#retry-unlock");
  const dismiss = root.querySelector("#dismiss");
  const revealBtn = root.querySelector("#reveal-toggle");
  const subtitle = root.querySelector("#main-subtitle");
  const toast = document.querySelector("#code-toast");

  let revealed = false;
  let refreshTimer = null;
  let toastTimer = null;
  let currentState = null;

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
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    revealed = false;
    revealBtn.classList.add("hidden");
    subtitle.textContent = "locked";
    showPane("awaiting");

    // Per spike #23: age-plugin-yubikey doesn't emit a touch-prompt
    // callback; the LED is the user signal. We invoke unlock the
    // moment AWAITING_TOUCH renders so the blink starts immediately.
    let result;
    try {
      result = await invoke("unlock");
    } catch (err) {
      handleUnlockError(err);
      return;
    }
    enterUnlocked(result.entries);
  };

  const handleUnlockError = (err) => {
    if (err && err.kind === "TouchTimeout") {
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

  // Wire interactions
  retry.addEventListener("click", () => enterAwaiting());

  dismiss.addEventListener("click", async () => {
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    // Same code path as tray-click-while-visible: drops the session
    // and hides the window. JS state resets on the next window:shown.
    try {
      await invoke("hide_window");
    } catch (err) {
      console.error("hide_window:", err);
    }
  });

  revealBtn.addEventListener("click", () => {
    revealed = !revealed;
    revealBtn.textContent = revealed ? "hide" : "eye";
    list.querySelectorAll(".digits").forEach((el) => {
      el.textContent = revealed ? formatCode(el.dataset.code) : "••• •••";
    });
  });

  // Backend emits "window:shown" when the user clicks the tray icon
  // to bring the popup up. Reset to AWAITING_TOUCH each time. We do
  // NOT auto-fire on DOMContentLoaded because the window is hidden at
  // launch (tauri.conf.json: visible=false) — the LED would blink
  // with the user unable to see it, time out, then fire again on the
  // first tray click. Window:shown is the only entry point.
  listen("window:shown", () => {
    enterAwaiting();
  });
}
