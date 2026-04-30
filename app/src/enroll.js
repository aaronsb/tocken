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
  const clipPane = root.querySelector('[data-step="clipboard"]');
  const camPane = root.querySelector('[data-step="camera"]');

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
    clipboard: "clipboard image",
    camera: "camera scan",
  };

  const showStep = (key) => {
    [sourcePane, pastePane, manualPane, filePane, clipPane, camPane].forEach(
      (p) => p.classList.add("hidden")
    );
    if (key === "source-picker") sourcePane.classList.remove("hidden");
    if (key === "paste") pastePane.classList.remove("hidden");
    if (key === "manual") manualPane.classList.remove("hidden");
    if (key === "file") filePane.classList.remove("hidden");
    if (key === "clipboard") clipPane.classList.remove("hidden");
    if (key === "camera") camPane.classList.remove("hidden");
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
    resetClipPane();
    resetCamPane();
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

  // Render a list of FileRowPreview objects into `listEl`. Shared by
  // the file-picker and clipboard-image sources; both surface the
  // same row state machine and feed the same enroll_file_commit call.
  const renderRowList = (listEl, rows) => {
    listEl.innerHTML = "";
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
      listEl.appendChild(li);
    });
    listEl.classList.remove("hidden");
  };

  // Read every checked row from `listEl`, look up its payload in
  // `rows`, and produce the {payload, force_weak} items the backend
  // expects. force_weak is implied by "row was weak AND user
  // checked it" — the unchecked default for weak rows is the opt-in
  // gesture per ADR-101.
  const collectSelectedItems = (listEl, rows) => {
    const items = [];
    listEl
      .querySelectorAll("input.enroll-file-row-include")
      .forEach((cb) => {
        if (!cb.checked) return;
        const row = rows[Number(cb.dataset.idx)];
        if (!row || !row.payload) return;
        items.push({ payload: row.payload, force_weak: !!row.weak_bits });
      });
    return items;
  };

  // Surface a `FileError`-shaped error onto an arbitrary status line.
  // Both file and clipboard sources funnel through this; some kinds
  // (Empty plaintext) only fire from the file path, others
  // (ClipboardEmpty) only from the clipboard path — but since the
  // type is shared the renderer covers both.
  const fileErrorMessage = (err) => {
    if (!err) return "Unknown error";
    if (err.kind === "empty") return "File is empty.";
    if (err.kind === "no_codes_found")
      return "No QR codes found in this image.";
    if (err.kind === "quality_too_low")
      return "QR detected but couldn't be decoded — try better focus, lighting, or moving closer.";
    if (err.kind === "clipboard_empty")
      return "No image on clipboard. Copy a QR code image first.";
    if (err.kind === "image")
      return `Image decode failed: ${err.detail || "unknown"}`;
    if (err.kind === "io")
      return `Could not read file: ${err.detail || "unknown"}`;
    return String(err.kind || err);
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
      showFileError(fileErrorMessage(err));
      return;
    }
    if (rows.length === 0) {
      showFileError("File contained no recognizable entries.");
      return;
    }
    fileRows = rows;
    renderRowList(fileRowsList, rows);
    filePick.classList.add("hidden");
    fileSubmit.classList.remove("hidden");
  };

  const submitFile = async () => {
    fileError.classList.add("hidden");
    const items = collectSelectedItems(fileRowsList, fileRows);
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

  // ─── Clipboard-image flow ─────────────────────────────────────────
  // Variant of the file flow: image bytes come from the clipboard
  // instead of disk, so there's no path to display and no destroy
  // prompt at the end. Read happens Rust-side via the clipboard-
  // manager plugin (arboard under the hood). The browser's
  // navigator.clipboard.read() is denied by WebKitGTK in Tauri
  // webviews on Linux even from a user-gesture context, so going
  // through the plugin is the only path that works cross-display-
  // server. Read is gated behind an explicit button click so the
  // user has a clear permission gesture.

  const clipStatus = root.querySelector("#enroll-clip-status");
  const clipError = root.querySelector("#enroll-clip-error");
  const clipRowsList = root.querySelector("#enroll-clip-rows");
  const clipSummary = root.querySelector("#enroll-clip-summary");
  const clipRead = root.querySelector("#enroll-clip-read");
  const clipSubmit = root.querySelector("#enroll-clip-submit");
  const clipDone = root.querySelector("#enroll-clip-done");

  let clipRows = [];

  const showClipError = (msg) => {
    clipError.textContent = msg;
    clipError.classList.remove("hidden");
  };

  const resetClipPane = () => {
    clipRows = [];
    clipStatus.textContent =
      "Copy a QR code image to your clipboard, then click Read.";
    clipStatus.classList.remove("hidden");
    clipError.classList.add("hidden");
    clipError.textContent = "";
    clipRowsList.classList.add("hidden");
    clipRowsList.innerHTML = "";
    clipSummary.classList.add("hidden");
    clipSummary.textContent = "";
    clipRead.classList.remove("hidden");
    clipSubmit.classList.add("hidden");
    clipDone.classList.add("hidden");
  };

  const readClipboardImage = async () => {
    clipError.classList.add("hidden");
    let rows;
    try {
      rows = await invoke("enroll_clipboard_image_preview");
    } catch (err) {
      showClipError(fileErrorMessage(err));
      return;
    }
    if (rows.length === 0) {
      showClipError("No recognizable entries in the clipboard image.");
      return;
    }
    clipRows = rows;
    clipStatus.textContent = `Decoded ${rows.length} ${rows.length === 1 ? "entry" : "entries"} from clipboard image.`;
    renderRowList(clipRowsList, rows);
    clipRead.classList.add("hidden");
    clipSubmit.classList.remove("hidden");
  };

  const submitClipboard = async () => {
    clipError.classList.add("hidden");
    const items = collectSelectedItems(clipRowsList, clipRows);
    if (items.length === 0) {
      showClipError("Nothing selected.");
      return;
    }
    let result;
    try {
      result = await invoke("enroll_file_commit", { items });
    } catch (err) {
      showClipError(errorMessageFor(err));
      return;
    }
    const added = result.outcomes.filter((o) => o.added_id).length;
    const errors = result.outcomes.filter((o) => o.error).length;
    let summary = `Added ${added} ${added === 1 ? "entry" : "entries"}.`;
    if (errors > 0)
      summary += ` ${errors} ${errors === 1 ? "row" : "rows"} skipped due to errors.`;
    clipSummary.textContent = summary;
    clipSummary.classList.remove("hidden");
    clipSubmit.classList.add("hidden");
    clipRowsList
      .querySelectorAll("input.enroll-file-row-include")
      .forEach((cb) => (cb.disabled = true));
    clipDone.classList.remove("hidden");
  };

  clipRead.addEventListener("click", readClipboardImage);
  clipSubmit.addEventListener("click", submitClipboard);
  clipDone.addEventListener("click", () => {
    onAdded();
  });

  // ─── Camera-scan flow ─────────────────────────────────────────────
  // getUserMedia → live <video> preview → per-frame jsQR decode in
  // the webview → on hit, stop stream + send the decoded payload
  // string (~hundreds of bytes) to the backend for the row preview.
  //
  // No binary IPC: we don't ship raw image bytes to Rust. The naive
  // approach (toBlob → Array.from(Uint8Array) → JSON over the IPC
  // pipe) was the dominant cost on the capture-to-preview round
  // trip. Decoding the QR in-process and sending only the payload
  // text sidesteps that entirely.
  //
  // Two Linux dependencies still apply:
  //   - WebKitGTK media-permission grant (handled in lib.rs setup)
  //   - gstreamer v4l2src for camera capture (gst-plugins-good)
  //
  // The MediaStream + scan loop are tied to the page lifetime via
  // `camStream` and `camScanReq` — resetCamPane() and back/done
  // flows MUST stop tracks AND cancel the rAF, or the OS camera
  // indicator stays lit and the loop keeps consuming CPU.

  const camStatus = root.querySelector("#enroll-cam-status");
  const camError = root.querySelector("#enroll-cam-error");
  const camVideo = root.querySelector("#enroll-cam-video");
  const camCanvas = root.querySelector("#enroll-cam-canvas");
  const camRowsList = root.querySelector("#enroll-cam-rows");
  const camSummary = root.querySelector("#enroll-cam-summary");
  const camStart = root.querySelector("#enroll-cam-start");
  const camStop = root.querySelector("#enroll-cam-stop");
  const camSubmit = root.querySelector("#enroll-cam-submit");
  const camDone = root.querySelector("#enroll-cam-done");

  let camStream = null;
  let camScanReq = null;
  let camRows = [];

  const showCamError = (msg) => {
    camError.textContent = msg;
    camError.classList.remove("hidden");
  };

  const stopCamStream = () => {
    if (camScanReq != null) {
      cancelAnimationFrame(camScanReq);
      camScanReq = null;
    }
    if (camStream) {
      camStream.getTracks().forEach((t) => t.stop());
      camStream = null;
    }
    camVideo.srcObject = null;
  };

  const resetCamPane = () => {
    stopCamStream();
    camRows = [];
    camStatus.textContent = "Click Start to open the camera.";
    camStatus.classList.remove("hidden");
    camError.classList.add("hidden");
    camError.textContent = "";
    camCanvas.classList.add("hidden");
    camRowsList.classList.add("hidden");
    camRowsList.innerHTML = "";
    camSummary.classList.add("hidden");
    camSummary.textContent = "";
    camStart.classList.remove("hidden");
    camStop.classList.add("hidden");
    camSubmit.classList.add("hidden");
    camDone.classList.add("hidden");
  };

  const startCamera = async () => {
    camError.classList.add("hidden");
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showCamError(
        "Camera API unavailable. On Linux this needs gst-plugins-good (v4l2src) — install it and restart the app."
      );
      return;
    }
    if (!window.jsQR) {
      showCamError("jsQR failed to load — check vendor/jsqr.js.");
      return;
    }
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
    } catch (err) {
      const name = err && err.name ? err.name : "";
      if (name === "NotAllowedError")
        showCamError("Camera permission denied.");
      else if (name === "NotFoundError")
        showCamError("No camera detected.");
      else if (name === "NotReadableError")
        showCamError(
          "Camera is busy or unavailable. On Linux this often means gst-plugins-good (v4l2src) is missing — install it and restart the app."
        );
      else showCamError(`Camera error: ${err && err.message ? err.message : err}`);
      return;
    }
    camStream = stream;
    camVideo.srcObject = stream;
    // The <video> stays hidden; the <canvas> is what's visible. The
    // scan loop does drawImage every frame anyway, so the canvas is
    // continuously updated.
    camCanvas.classList.remove("hidden");
    camStatus.textContent = "Looking for a QR — line up the code.";
    camStart.classList.add("hidden");
    camStop.classList.remove("hidden");

    // WebKitGTK doesn't reliably honor the `autoplay` attribute
    // when srcObject changes after first paint — the LED comes on
    // (stream acquired) but the <video> stays a black region until
    // .play() is called explicitly. The promise rejects in some
    // hardened webview policies; we don't want a permission failure
    // to leave the stream hanging.
    try {
      await camVideo.play();
    } catch (err) {
      stopCamStream();
      showCamError(`Could not start video playback: ${err && err.message ? err.message : err}`);
      camStart.classList.remove("hidden");
      camStop.classList.add("hidden");
      return;
    }

    // Don't schedule scanning until the video element has frames
    // available — `videoWidth` is 0 before `loadedmetadata`, and
    // `getImageData` on a 0×0 canvas returns nothing useful.
    if (camVideo.readyState < 2 /* HAVE_CURRENT_DATA */) {
      await new Promise((resolve) => {
        const onReady = () => {
          camVideo.removeEventListener("loadeddata", onReady);
          resolve();
        };
        camVideo.addEventListener("loadeddata", onReady);
      });
    }

    if (!camStream) return; // user hit Stop while we were waiting
    camScanReq = requestAnimationFrame(scanFrame);
  };

  // Per-frame decode loop. Pulls the current <video> frame into a
  // canvas, runs jsQR over the ImageData, and on a hit hands off
  // the decoded payload to the backend. dontInvert mirrors most
  // real-world QR captures and skips an inversion pass jsQR does
  // by default — meaningful CPU win on the per-frame hot path.
  const scanFrame = async () => {
    if (!camStream) return; // stopped between scheduling and dispatch
    if (!camVideo.videoWidth) {
      camScanReq = requestAnimationFrame(scanFrame);
      return;
    }
    camCanvas.width = camVideo.videoWidth;
    camCanvas.height = camVideo.videoHeight;
    const ctx = camCanvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(camVideo, 0, 0);
    const data = ctx.getImageData(0, 0, camCanvas.width, camCanvas.height);

    const code = window.jsQR(data.data, data.width, data.height, {
      inversionAttempts: "dontInvert",
    });

    if (!code) {
      camScanReq = requestAnimationFrame(scanFrame);
      return;
    }

    // Got a hit. Stop scanning before the IPC roundtrip so the
    // camera releases promptly even if the backend is slow.
    stopCamStream();
    camCanvas.classList.add("hidden");
    camStop.classList.add("hidden");
    camStatus.textContent = "QR detected. Reviewing…";

    let rows;
    try {
      rows = await invoke("enroll_payloads_preview", {
        payloads: [code.data],
      });
    } catch (err) {
      showCamError(fileErrorMessage(err));
      // Surface a Start button so the user can try again.
      camStart.classList.remove("hidden");
      return;
    }
    if (rows.length === 0) {
      showCamError("Decoded QR but no recognizable entry.");
      camStart.classList.remove("hidden");
      return;
    }
    camRows = rows;
    camStatus.textContent = `Captured ${rows.length} ${rows.length === 1 ? "entry" : "entries"}. Review below.`;
    renderRowList(camRowsList, rows);
    camSubmit.classList.remove("hidden");
  };

  const submitCamera = async () => {
    camError.classList.add("hidden");
    const items = collectSelectedItems(camRowsList, camRows);
    if (items.length === 0) {
      showCamError("Nothing selected.");
      return;
    }
    let result;
    try {
      result = await invoke("enroll_file_commit", { items });
    } catch (err) {
      showCamError(errorMessageFor(err));
      return;
    }
    const added = result.outcomes.filter((o) => o.added_id).length;
    const errors = result.outcomes.filter((o) => o.error).length;
    let summary = `Added ${added} ${added === 1 ? "entry" : "entries"}.`;
    if (errors > 0)
      summary += ` ${errors} ${errors === 1 ? "row" : "rows"} skipped due to errors.`;
    camSummary.textContent = summary;
    camSummary.classList.remove("hidden");
    camSubmit.classList.add("hidden");
    camRowsList
      .querySelectorAll("input.enroll-file-row-include")
      .forEach((cb) => (cb.disabled = true));
    camDone.classList.remove("hidden");
  };

  camStart.addEventListener("click", startCamera);
  camStop.addEventListener("click", () => {
    stopCamStream();
    resetCamPane();
  });
  camSubmit.addEventListener("click", submitCamera);
  camDone.addEventListener("click", () => {
    stopCamStream();
    onAdded();
  });

  // Cancel surfaces (Escape, etc.) — wired by the caller via reset
  // before re-show, so just expose the lifecycle hook.
  return {
    reset,
    cancel: () => onCancel(),
  };
}
