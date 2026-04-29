const { invoke } = window.__TAURI__.core;

const WIZARD_STEPS = ["welcome", "passphrase", "confirm", "yubikey", "location", "done"];

window.addEventListener("DOMContentLoaded", async () => {
  const mainPanel = document.querySelector("#main-panel");
  const wizard = document.querySelector("#wizard");

  try {
    const initialized = await invoke("is_initialized");
    if (initialized) {
      mainPanel.classList.remove("hidden");
    } else {
      wizard.classList.remove("hidden");
      initWizard(wizard);
    }
  } catch (err) {
    // Fail open to main panel; wizard logic comes online in subsequent tasks.
    console.error("is_initialized failed:", err);
    mainPanel.classList.remove("hidden");
  }

  const btn = document.querySelector("#touch-btn");
  const status = document.querySelector("#status");
  const details = document.querySelector("#details-body");
  const ctxMenu = document.querySelector("#ctx-menu");
  const ctxCopy = document.querySelector("#ctx-copy");
  const ctxSelectAll = document.querySelector("#ctx-select-all");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.textContent = "Touch your YubiKey now…";
    status.className = "status pending";
    details.textContent = "";
    try {
      const result = await invoke("verify_touch");
      status.textContent = result.message;
      status.className = "status ok";
      details.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      status.textContent = String(err);
      status.className = "status err";
      details.textContent = String(err);
    } finally {
      btn.disabled = false;
    }
  });

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
    const sel = window.getSelection().toString();
    const text = sel || details.textContent || status.textContent;
    if (text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
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
    const range = document.createRange();
    range.selectNodeContents(details);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    hideCtx();
  });
});

// Wizard state machine. Each step has an `enter` handler that runs
// when the pane shows. Steps may set state on `ctx` and gate the next
// transition by leaving the [data-next] button disabled.
function initWizard(root) {
  const { listen } = window.__TAURI__.event;
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

  // Generic next-button delegation. Handlers can disable individual
  // buttons to gate progress (e.g. confirm pane requires the typed
  // phrase before its [data-next] becomes enabled).
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

      // Not provisioned — show the Provision pane.
      status.textContent =
        "No age identity on this YubiKey yet. Plug it in and click Provision. You'll be asked to touch the key.";
      provisionBtn.classList.remove("hidden");
      provisionBtn.disabled = false;

      if (provisionBtn.dataset.bound) return;
      provisionBtn.dataset.bound = "1";

      // Stream provisioning output as the subprocess emits it.
      const unlisten = await listen("wizard:provision-output", (event) => {
        output.textContent += `${event.payload}\n`;
        output.scrollTop = output.scrollHeight;
      });

      provisionBtn.addEventListener("click", async () => {
        // Double-click guard: any concurrent age-plugin-yubikey
        // --generate would race the PIV slot.
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
            output.textContent += `\n${ctx.pinPukMessage}\n\n` +
              "Save the PIN/PUK above offline — needed only for PIV admin operations.";
          }
          next.classList.remove("hidden");
          unlisten();
        } catch (err) {
          status.textContent = `Provisioning failed: ${err}`;
          provisionBtn.disabled = false; // allow Retry
        }
      });
    },

    location: (pane) => {
      const display = pane.querySelector("#wizard-location");
      // Could resolve via a Tauri command, but XDG defaults are stable
      // and finalize_init returns the actual paths on the next pane.
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
        // Hand off to the main panel. Reload is the simplest re-init.
        window.location.reload();
      });
    },
  };

  showStep(0);
}
