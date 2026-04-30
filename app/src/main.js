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
      const heading = pane.querySelector("#wizard-done-heading");
      const status = pane.querySelector("#wizard-done-status");
      finish.disabled = true;
      heading.textContent = "Verify setup";

      try {
        await invoke("finalize_init", {
          passphrase: ctx.passphrase,
          yubikeyRecipient: ctx.yubikeyRecipient,
        });
        status.textContent =
          "Touch your YubiKey to open your new store for the first time.";
      } catch (err) {
        heading.textContent = "Setup failed";
        status.textContent = `${err}`;
        finish.disabled = false;
        bindFinish(finish);
        return;
      }

      // Verification unlock: catches any setup mismatch (slot /
      // identity / pathing) inside the wizard rather than dropping the
      // user onto the main panel mid-touch. Leaves the session
      // unlocked; main-panel post-reload sees the active session and
      // skips its own unlock prompt.
      try {
        await invoke("unlock");
        heading.textContent = "Setup complete";
        status.textContent =
          "Your store is ready. No accounts will exist on a new store yet — enrollment lands in #6.";
        finish.disabled = false;
      } catch (err) {
        heading.textContent = "Verification failed";
        if (err && err.kind === "TouchTimeout") {
          status.textContent =
            "No touch detected. Click Open and try again from the main panel.";
        } else {
          status.textContent = `${err && err.kind ? err.kind : err}. Click Open to retry from the main panel.`;
        }
        finish.disabled = false;
      }

      bindFinish(finish);
    },
  };

  function bindFinish(finish) {
    if (finish.dataset.bound) return;
    finish.dataset.bound = "1";
    finish.addEventListener("click", () => {
      // Reload re-runs is_initialized: on success it lands on the
      // main panel; on prior finalize_init failure (no store written)
      // it re-enters the wizard from welcome — a clean retry.
      window.location.reload();
    });
  };

  showStep(0);
}

// ─────────────────────────────────────────────────────────────────────
// Code panel state machine (issue #3)
// ─────────────────────────────────────────────────────────────────────

async function initCodePanel(root) {
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

// Enrollment panel — source picker + paste-URI textarea + manual form.
// Each source feeds the same backend pipeline: input goes through
// validate, weak-secret check (ADR-101), then commit. The weak-secret
// confirmation surface is an inline notice above the submit button —
// per the user's UX guidance, informational and in-flow, not a modal
// (and never shown during code display, only enrollment).
function initEnrollPanel(root, { onCancel, onAdded }) {
  const stepLabel = root.querySelector("#enroll-step-label");
  const sourcePane = root.querySelector('[data-step="source-picker"]');
  const pastePane = root.querySelector('[data-step="paste"]');
  const manualPane = root.querySelector('[data-step="manual"]');

  const uriInput = root.querySelector("#enroll-uri-input");
  const uriError = root.querySelector("#enroll-uri-error");
  const uriWeak = root.querySelector("#enroll-uri-weak");
  const uriSubmit = root.querySelector("#enroll-uri-submit");

  const manualForm = root.querySelector("#enroll-manual-form");
  const manualError = root.querySelector("#enroll-manual-error");
  const manualWeak = root.querySelector("#enroll-manual-weak");
  const manualSubmit = root.querySelector("#enroll-manual-submit");

  // Per-pane "weak-secret confirmed" flag. Cleared on every input
  // change so a stale Use-anyway click can't ride past a typo.
  let pasteForceWeak = false;
  let manualForceWeak = false;

  const labelMap = {
    "source-picker": "choose source",
    paste: "paste URI",
    manual: "manual entry",
  };

  const showStep = (key) => {
    [sourcePane, pastePane, manualPane].forEach((p) =>
      p.classList.add("hidden")
    );
    if (key === "source-picker") sourcePane.classList.remove("hidden");
    if (key === "paste") pastePane.classList.remove("hidden");
    if (key === "manual") manualPane.classList.remove("hidden");
    stepLabel.textContent = labelMap[key] || "";
  };

  const reset = () => {
    showStep("source-picker");
    uriInput.value = "";
    uriError.classList.add("hidden");
    uriWeak.classList.add("hidden");
    uriSubmit.textContent = "Add";
    pasteForceWeak = false;
    manualForm.reset();
    manualError.classList.add("hidden");
    manualWeak.classList.add("hidden");
    manualSubmit.textContent = "Add";
    manualForceWeak = false;
  };

  // Surface an EnrollError onto a paste/manual error+weak pair.
  // Returns true if the error was a WeakSecret notice (caller should
  // flip the local force flag and update the submit label).
  const renderError = (err, errorEl, weakEl, submitEl) => {
    errorEl.classList.add("hidden");
    weakEl.classList.add("hidden");
    if (err && err.kind === "weak_secret") {
      weakEl.textContent =
        `This service issues a non-standard short secret (${err.bits} bits, ` +
        "less than the 128-bit RFC minimum). tocken cannot lengthen it. " +
        "Most authenticators accept these. Use anyway?";
      weakEl.classList.remove("hidden");
      submitEl.textContent = "Use anyway";
      return true;
    }
    if (err && err.kind === "locked") {
      errorEl.textContent = "Session re-locked. Close this and unlock again.";
    } else if (err && err.kind === "save_failed") {
      errorEl.textContent = `Could not save: ${err.detail || "unknown error"}`;
    } else if (err && err.kind === "invalid_secret") {
      errorEl.textContent = "Secret is not valid base32.";
    } else if (err && err.kind === "invalid_digits") {
      errorEl.textContent = `Digits must be 6, 7, or 8 (got ${err.digits}).`;
    } else if (err && err.kind === "invalid_period") {
      errorEl.textContent =
        `Period must be between 1 and 86400 seconds (got ${err.period}).`;
    } else if (err && err.kind === "missing_account") {
      errorEl.textContent = "Account is required.";
    } else if (err && err.kind === "invalid_uri") {
      errorEl.textContent = `Could not parse URI: ${err.detail || "unknown"}`;
    } else if (err && err.kind === "migration_uri_not_supported") {
      errorEl.textContent =
        "Google Authenticator export URIs (otpauth-migration://) are not yet supported.";
    } else if (err && err.kind === "hotp_not_supported") {
      errorEl.textContent = "HOTP enrollment is not yet supported.";
    } else {
      errorEl.textContent =
        err && err.kind ? err.kind : String(err);
    }
    errorEl.classList.remove("hidden");
    return false;
  };

  // Source picker
  sourcePane.querySelectorAll("[data-source]").forEach((btn) =>
    btn.addEventListener("click", () => {
      showStep(btn.dataset.source);
    })
  );
  root.querySelector("#enroll-cancel").addEventListener("click", () =>
    onCancel()
  );

  // Back buttons return to picker
  root.querySelectorAll("[data-back]").forEach((btn) =>
    btn.addEventListener("click", () => reset())
  );

  // Clearing input invalidates a previous Use-anyway confirmation —
  // require a fresh prompt if the secret bits changed.
  uriInput.addEventListener("input", () => {
    pasteForceWeak = false;
    uriWeak.classList.add("hidden");
    uriSubmit.textContent = "Add";
  });
  manualForm.addEventListener("input", (e) => {
    if (e.target.name === "secret") {
      manualForceWeak = false;
      manualWeak.classList.add("hidden");
      manualSubmit.textContent = "Add";
    }
  });

  // Paste-URI submit
  uriSubmit.addEventListener("click", async () => {
    const uri = uriInput.value.trim();
    if (!uri) {
      uriError.textContent = "Paste a URI first.";
      uriError.classList.remove("hidden");
      return;
    }
    try {
      await invoke("enroll_uri", { uri, forceWeak: pasteForceWeak });
      onAdded();
    } catch (err) {
      const becameWeak = renderError(err, uriError, uriWeak, uriSubmit);
      if (becameWeak) pasteForceWeak = true;
    }
  });

  // Manual-form submit
  manualForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(manualForm);
    const form = {
      issuer: (data.get("issuer") || "").trim(),
      account: (data.get("account") || "").trim(),
      secret: data.get("secret") || "",
      digits: Number(data.get("digits")),
      period: Number(data.get("period")),
      algorithm: data.get("algorithm"),
      kind: "totp",
    };
    try {
      await invoke("enroll_manual", { form, forceWeak: manualForceWeak });
      onAdded();
    } catch (err) {
      const becameWeak = renderError(
        err,
        manualError,
        manualWeak,
        manualSubmit
      );
      if (becameWeak) manualForceWeak = true;
    }
  });

  // Cancel surfaces (Escape, etc.) — wired by the caller via reset
  // before re-show, so just expose the lifecycle hook.
  return {
    reset,
    cancel: () => onCancel(),
  };
}
