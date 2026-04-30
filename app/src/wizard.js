// First-run wizard state machine (issue #5). Linear pane sequence:
// welcome → passphrase → confirm → yubikey → location → done. The
// last step performs a verification unlock so any setup mismatch
// (slot / identity / pathing) surfaces inside the wizard rather than
// dropping the user onto the main panel mid-touch.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const WIZARD_STEPS = ["welcome", "passphrase", "confirm", "yubikey", "location", "done"];

export function initWizard(root) {
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
