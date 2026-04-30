// Enrollment panel — source picker + paste-URI textarea + manual form.
// Each source feeds the same backend pipeline: input goes through
// validate, weak-secret check (ADR-101), then commit. The weak-secret
// confirmation surface is an inline notice above the submit button —
// per the user's UX guidance, informational and in-flow, not a modal
// (and never shown during code display, only enrollment).

const { invoke } = window.__TAURI__.core;

export function initEnrollPanel(root, { onCancel, onAdded }) {
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
