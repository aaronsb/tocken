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
  const filePane = root.querySelector('[data-step="file"]');

  const uriInput = root.querySelector("#enroll-uri-input");
  const uriError = root.querySelector("#enroll-uri-error");
  const uriWeak = root.querySelector("#enroll-uri-weak");
  const uriSubmit = root.querySelector("#enroll-uri-submit");

  const manualForm = root.querySelector("#enroll-manual-form");
  const manualError = root.querySelector("#enroll-manual-error");
  const manualWeak = root.querySelector("#enroll-manual-weak");
  const manualSubmit = root.querySelector("#enroll-manual-submit");

  const fileStatus = root.querySelector("#enroll-file-status");
  const fileError = root.querySelector("#enroll-file-error");
  const fileRowsList = root.querySelector("#enroll-file-rows");
  const fileSummary = root.querySelector("#enroll-file-summary");
  const fileDestroyPrompt = root.querySelector("#enroll-file-destroy-prompt");
  const fileDestroy = root.querySelector("#enroll-file-destroy");
  const fileKeep = root.querySelector("#enroll-file-keep");
  const filePick = root.querySelector("#enroll-file-pick");
  const fileSubmit = root.querySelector("#enroll-file-submit");
  const fileDone = root.querySelector("#enroll-file-done");

  // Per-pane "weak-secret confirmed" flag. Cleared on every input
  // change so a stale Use-anyway click can't ride past a typo.
  let pasteForceWeak = false;
  let manualForceWeak = false;
  // File-source state: previewed rows + the source path. The path is
  // remembered so the post-commit destroy prompt knows what to delete.
  let filePath = null;
  let fileRows = [];

  const labelMap = {
    "source-picker": "choose source",
    paste: "paste URI",
    manual: "manual entry",
    file: "file picker",
  };

  const showStep = (key) => {
    [sourcePane, pastePane, manualPane, filePane].forEach((p) =>
      p.classList.add("hidden")
    );
    if (key === "source-picker") sourcePane.classList.remove("hidden");
    if (key === "paste") pastePane.classList.remove("hidden");
    if (key === "manual") manualPane.classList.remove("hidden");
    if (key === "file") filePane.classList.remove("hidden");
    stepLabel.textContent = labelMap[key] || "";
  };

  const resetFilePane = () => {
    filePath = null;
    fileRows = [];
    fileStatus.textContent =
      "Pick a file containing one or more otpauth:// URIs (plaintext, one per line) or QR codes (PNG/JPG).";
    fileStatus.classList.remove("hidden");
    fileError.classList.add("hidden");
    fileError.textContent = "";
    fileRowsList.classList.add("hidden");
    fileRowsList.innerHTML = "";
    fileSummary.classList.add("hidden");
    fileSummary.textContent = "";
    fileDestroyPrompt.classList.add("hidden");
    filePick.classList.remove("hidden");
    fileSubmit.classList.add("hidden");
    fileDone.classList.add("hidden");
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
    resetFilePane();
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

  // ─── File-source flow ─────────────────────────────────────────────
  // pick → preview → commit → summary → (destroy | keep) → done.
  // The dialog plugin is invoked directly via plugin command rather
  // than the JS package: no bundler in use, so `import { open } from
  // '@tauri-apps/plugin-dialog'` would fail at runtime. The command
  // wire format is documented in the plugin's guest-js source.

  const errorMessageFor = (err) => {
    if (!err) return "Unknown error";
    if (err.kind === "weak_secret")
      return `Weak secret (${err.bits} bits)`;
    if (err.kind === "invalid_secret") return "Invalid base32 secret";
    if (err.kind === "invalid_digits")
      return `Invalid digits (${err.digits})`;
    if (err.kind === "invalid_period")
      return `Invalid period (${err.period}s)`;
    if (err.kind === "missing_account") return "Missing account";
    if (err.kind === "invalid_uri")
      return `Cannot parse URI: ${err.detail || "unknown"}`;
    if (err.kind === "migration_uri_not_supported")
      return "Google Authenticator export URI — needs #7";
    if (err.kind === "hotp_not_supported") return "HOTP not yet supported";
    if (err.kind === "locked") return "Session locked";
    if (err.kind === "save_failed")
      return `Save failed: ${err.detail || "unknown"}`;
    return err.kind || String(err);
  };

  const renderFileRows = (rows) => {
    fileRowsList.innerHTML = "";
    rows.forEach((row, idx) => {
      const li = document.createElement("li");
      li.className = "enroll-file-row";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "enroll-file-row-include";
      cb.dataset.idx = String(idx);
      cb.disabled = !!row.error;
      // Default state: include valid rows; weak rows start unchecked
      // so the user has to opt in (mirrors the paste-URI "Use anyway"
      // gesture).
      cb.checked = !row.error && !row.weak_bits;
      li.appendChild(cb);

      const meta = document.createElement("div");
      meta.className = "enroll-file-row-meta";
      const title = document.createElement("div");
      title.className = "enroll-file-row-title";
      if (row.error) {
        title.textContent = row.source;
        title.classList.add("enroll-file-row-error-title");
      } else {
        const issuer = row.issuer || "(no issuer)";
        const account = row.account || "(no account)";
        title.textContent = `${issuer} — ${account}`;
      }
      meta.appendChild(title);

      const detail = document.createElement("div");
      detail.className = "enroll-file-row-detail";
      if (row.error) {
        detail.textContent = errorMessageFor(row.error);
        detail.classList.add("err");
      } else if (row.weak_bits) {
        detail.textContent = `weak secret (${row.weak_bits} bits, RFC minimum 128) — check to use anyway`;
        detail.classList.add("warn");
      } else {
        detail.textContent = `${row.digits} digits / ${row.period}s`;
      }
      meta.appendChild(detail);

      li.appendChild(meta);
      fileRowsList.appendChild(li);
    });
    fileRowsList.classList.remove("hidden");
  };

  const showFileError = (msg) => {
    fileError.textContent = msg;
    fileError.classList.remove("hidden");
  };

  const pickFile = async () => {
    fileError.classList.add("hidden");
    let path;
    try {
      path = await invoke("plugin:dialog|open", {
        options: {
          multiple: false,
          directory: false,
          filters: [
            {
              name: "Token sources",
              extensions: ["png", "jpg", "jpeg", "txt", "uri", "list"],
            },
            { name: "All files", extensions: ["*"] },
          ],
        },
      });
    } catch (err) {
      showFileError(`Could not open dialog: ${err}`);
      return;
    }
    if (!path) return; // user cancelled
    filePath = path;
    fileStatus.textContent = path;

    let rows;
    try {
      rows = await invoke("enroll_file_preview", { path });
    } catch (err) {
      if (err && err.kind === "empty") showFileError("File is empty.");
      else if (err && err.kind === "no_codes_found")
        showFileError("No QR codes found in this image.");
      else if (err && err.kind === "image")
        showFileError(`Image decode failed: ${err.detail || "unknown"}`);
      else if (err && err.kind === "io")
        showFileError(`Could not read file: ${err.detail || "unknown"}`);
      else showFileError(String(err && err.kind ? err.kind : err));
      return;
    }
    if (rows.length === 0) {
      showFileError("File contained no recognizable entries.");
      return;
    }
    fileRows = rows;
    renderFileRows(rows);
    filePick.classList.add("hidden");
    fileSubmit.classList.remove("hidden");
  };

  const submitFile = async () => {
    fileError.classList.add("hidden");
    const checks = Array.from(
      fileRowsList.querySelectorAll("input.enroll-file-row-include")
    );
    const items = [];
    for (const cb of checks) {
      if (!cb.checked) continue;
      const idx = Number(cb.dataset.idx);
      const row = fileRows[idx];
      if (!row || !row.payload) continue;
      items.push({
        payload: row.payload,
        force_weak: !!row.weak_bits, // checked-with-weak-bits implies user opt-in
      });
    }
    if (items.length === 0) {
      showFileError("Nothing selected.");
      return;
    }

    let result;
    try {
      result = await invoke("enroll_file_commit", { items });
    } catch (err) {
      showFileError(errorMessageFor(err));
      return;
    }

    const added = result.outcomes.filter((o) => o.added_id).length;
    const errors = result.outcomes.filter((o) => o.error).length;
    let summary = `Added ${added} ${added === 1 ? "entry" : "entries"}.`;
    if (errors > 0)
      summary += ` ${errors} ${errors === 1 ? "row" : "rows"} skipped due to errors.`;
    fileSummary.textContent = summary;
    fileSummary.classList.remove("hidden");
    fileSubmit.classList.add("hidden");
    // Disable all checkboxes after commit so the user can't re-submit.
    fileRowsList
      .querySelectorAll("input.enroll-file-row-include")
      .forEach((cb) => (cb.disabled = true));

    fileDestroyPrompt.classList.remove("hidden");
    fileDone.classList.remove("hidden");
  };

  const destroySource = async () => {
    if (!filePath) return;
    try {
      await invoke("destroy_source_file", { path: filePath });
      fileSummary.textContent =
        (fileSummary.textContent || "") + " Source file overwritten and deleted.";
    } catch (err) {
      showFileError(`Destroy failed: ${err}`);
      return;
    }
    fileDestroyPrompt.classList.add("hidden");
  };

  filePick.addEventListener("click", pickFile);
  fileSubmit.addEventListener("click", submitFile);
  fileDestroy.addEventListener("click", destroySource);
  fileKeep.addEventListener("click", () => {
    fileDestroyPrompt.classList.add("hidden");
  });
  fileDone.addEventListener("click", () => {
    onAdded();
  });

  // Cancel surfaces (Escape, etc.) — wired by the caller via reset
  // before re-show, so just expose the lifecycle hook.
  return {
    reset,
    cancel: () => onCancel(),
  };
}
