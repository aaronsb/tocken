//! Enrollment wiring: paste-URI / manual / file picker. Single
//! commit pipeline: normalize → vet → finalize → store.add_entry →
//! store.save → rebuild Session.

use std::thread;

use secrecy::{ExposeSecret, SecretString};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use tocken_core::enroll::{self, EnrollError, EnrollForm};
use tocken_core::session::Session;
use tocken_core::store::format::{Algorithm, Entry, EntryKind};

use crate::code_panel::tick_codes;
use crate::{AppState, FilePreviewRow, MainWindow, SharedUnlocked};

pub(crate) fn wire_enroll(ui: &MainWindow, unlocked: SharedUnlocked) {
    {
        let weak = ui.as_weak();
        ui.global::<AppState>().on_open_enroll(move || {
            if let Some(ui) = weak.upgrade() {
                clear_enroll_state(&ui);
                ui.global::<AppState>().set_mode(3);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<AppState>().on_cancel_enroll(move || {
            if let Some(ui) = weak.upgrade() {
                // Skip clear_enroll_state — state resets on the next
                // `on_open_enroll`. See note in `wire_save_enroll`.
                ui.global::<AppState>().set_mode(2);
            }
        });
    }
    wire_save_enroll(ui, unlocked.clone(), false);
    wire_save_enroll(ui, unlocked.clone(), true);
    wire_choose_enroll_file(ui);
    wire_read_enroll_clipboard(ui);
    wire_save_enroll_file(ui, unlocked);
    wire_toggle_file_row(ui);
}

/// Per-row checkbox handler. Slint passes the row's `for[i]` index;
/// we mutate the model entry in place via `set_row_data`. Error rows
/// have no checkbox at all (the `.slint` `if row.error == ""` branch
/// hides it), so a stray index for an error row is a no-op.
fn wire_toggle_file_row(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_toggle_file_row(move |index| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let model = ui.global::<AppState>().get_enroll_file_rows();
        let idx = index as usize;
        let Some(mut row) = model.row_data(idx) else {
            return;
        };
        if !row.error.is_empty() {
            return;
        }
        row.selected = !row.selected;
        model.set_row_data(idx, row);
    });
}

fn clear_enroll_state(ui: &MainWindow) {
    let state = ui.global::<AppState>();
    state.set_enroll_source(0);
    state.set_enroll_uri("".into());
    state.set_enroll_issuer("".into());
    state.set_enroll_account("".into());
    state.set_enroll_secret("".into());
    state.set_enroll_digits("6".into());
    state.set_enroll_period("30".into());
    state.set_enroll_error("".into());
    state.set_enroll_weak_prompt(false);
    state.set_enroll_weak_bits(0);
    state.set_enroll_saving(false);
    state.set_enroll_file_path("".into());
    state.set_enroll_file_loading(false);
    state.set_enroll_clipboard_loading(false);
    state.set_enroll_file_rows(empty_file_rows());
    state.set_enroll_file_valid(0);
    state.set_enroll_file_weak(0);
    state.set_enroll_file_error(0);
    state.set_enroll_destroy_source(false);
}

fn empty_file_rows() -> ModelRc<FilePreviewRow> {
    ModelRc::new(VecModel::from(Vec::<FilePreviewRow>::new()))
}

/// Wire either `on_save_enroll` (force_weak=false) or
/// `on_save_enroll_force` (force_weak=true). Both share a body — only
/// the flag passed to `vet_form` differs.
fn wire_save_enroll(ui: &MainWindow, unlocked: SharedUnlocked, force_weak: bool) {
    let weak = ui.as_weak();
    let unlocked = unlocked.clone();
    let handler = move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_enroll_error("".into());
        state.set_enroll_saving(true);

        let form_result = match state.get_enroll_source() {
            0 => parse_paste_form(&state),
            1 => Ok(build_manual_form(&state)),
            other => Err(EnrollError::InvalidUri {
                detail: format!("unknown source {other}"),
            }),
        };

        let form = match form_result {
            Ok(f) => f,
            Err(e) => {
                state.set_enroll_saving(false);
                state.set_enroll_error(e.to_string().into());
                return;
            }
        };

        match commit_form(&unlocked, form, force_weak) {
            Ok(()) => {
                // Don't call clear_enroll_state here. Mutating
                // enrollment properties (especially enroll_source)
                // while EnrollmentPane is still mounted triggers a
                // transient remount of sibling sub-panes, and Slint
                // panics in `WindowItem::resolved_default_font_size`
                // during that race. State is cleared on the next
                // `on_open_enroll` instead.
                ui.global::<AppState>().set_mode(2);
                tick_codes(&ui, &unlocked);
            }
            Err(EnrollError::WeakSecret { bits }) => {
                state.set_enroll_saving(false);
                state.set_enroll_weak_bits(bits as i32);
                state.set_enroll_weak_prompt(true);
            }
            Err(e) => {
                state.set_enroll_saving(false);
                state.set_enroll_error(e.to_string().into());
            }
        }
    };
    if force_weak {
        ui.global::<AppState>().on_save_enroll_force(handler);
    } else {
        ui.global::<AppState>().on_save_enroll(handler);
    }
}

fn parse_paste_form(state: &AppState<'_>) -> Result<EnrollForm, EnrollError> {
    let uri = state.get_enroll_uri().to_string();
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(EnrollError::InvalidUri {
            detail: "no URI entered".into(),
        });
    }
    enroll::parse::parse_otpauth_uri(trimmed)
}

/// Build an `EnrollForm` from the manual-entry form fields. `digits`
/// and `period` are typed as text in Slint so the user can edit
/// freely; we parse here with a fall-through to the RFC defaults if
/// the field is empty or non-numeric. Range validation
/// (`6..=8` digits, `1..=86400` period) is left to
/// `enroll::vet_form` so the error surfaces through the same path
/// every other invalid form takes.
fn build_manual_form(state: &AppState<'_>) -> EnrollForm {
    let digits = state.get_enroll_digits().trim().parse::<u8>().unwrap_or(6);
    let period = state
        .get_enroll_period()
        .trim()
        .parse::<u32>()
        .unwrap_or(30);
    EnrollForm {
        issuer: state.get_enroll_issuer().to_string(),
        account: state.get_enroll_account().to_string(),
        secret: SecretString::from(state.get_enroll_secret().to_string()),
        digits,
        period,
        algorithm: Algorithm::Sha1,
        kind: EntryKind::Totp,
    }
}

/// Normalize the secret, run the validate + weak-check pipeline,
/// finalize, and commit to the store. Re-encrypt on save uses the
/// recipient set already in `Store` (master pubkey + recipients.txt
/// extras), so this path needs no fresh YubiKey touch — same property
/// the Tauri version relied on (ADR-100 §6).
fn commit_form(
    unlocked: &SharedUnlocked,
    mut form: EnrollForm,
    force_weak: bool,
) -> Result<(), EnrollError> {
    let normalized = enroll::normalize_secret(form.secret.expose_secret());
    form.secret = SecretString::from(normalized);

    enroll::vet_form(&form, force_weak)?;

    let entry = enroll::finalize_entry(form);
    add_entry_and_save(unlocked, entry)
}

fn add_entry_and_save(unlocked: &SharedUnlocked, entry: Entry) -> Result<(), EnrollError> {
    let mut guard = unlocked.lock().unwrap();
    let Some(u) = guard.as_mut() else {
        return Err(EnrollError::Locked);
    };
    u.store.add_entry(entry);
    u.store.save().map_err(|e| EnrollError::SaveFailed {
        detail: format!("{e}"),
    })?;
    let unlocked_at = u.session.unlocked_at_unix();
    u.session = Session::new(u.store.entries().to_vec(), unlocked_at);
    Ok(())
}

fn wire_choose_enroll_file(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_choose_enroll_file(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_enroll_file_loading(true);
        state.set_enroll_error("".into());

        let weak_done = weak.clone();
        thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Choose URI list or QR image")
                .pick_file();

            let outcome: Result<(String, Vec<enroll::file::FileRowPreview>), String> = match picked
            {
                None => Ok((String::new(), Vec::new())),
                Some(path) => match enroll::file::decode_file(&path) {
                    Ok(rows) => Ok((path.display().to_string(), rows)),
                    Err(e) => Err(format!("{e}")),
                },
            };

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                let state = ui.global::<AppState>();
                state.set_enroll_file_loading(false);
                match outcome {
                    Ok((path, rows)) => apply_decoded_rows(&state, path, rows),
                    Err(msg) => clear_decoded_rows(&state, msg),
                }
            });
        });
    });
}

/// Read a QR-bearing image from the OS clipboard and feed it through
/// the same `decode_payloads` → `FileRowPreview` pipeline the file
/// picker uses. The shared `enroll-file-rows` model + `save-enroll-file`
/// commit path mean the only clipboard-specific state is the loading
/// flag and the empty source path (which keeps destroy-source from
/// firing on the saved entries).
///
/// The same `apply_decoded_rows` helper will serve the camera path
/// in the next stage — `nokhwa` yields the same RGBA bytes per frame,
/// so on a successful `decode_rgba` it would call right into here.
fn wire_read_enroll_clipboard(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_read_enroll_clipboard(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_enroll_clipboard_loading(true);
        state.set_enroll_error("".into());

        let weak_done = weak.clone();
        thread::spawn(move || {
            let outcome = grab_clipboard_image_rows();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                let state = ui.global::<AppState>();
                state.set_enroll_clipboard_loading(false);
                match outcome {
                    // Empty path = no source file to delete; keeps
                    // destroy-source inert for clipboard imports.
                    Ok(rows) => apply_decoded_rows(&state, String::new(), rows),
                    Err(msg) => clear_decoded_rows(&state, msg),
                }
            });
        });
    });
}

/// One-shot clipboard read on a worker thread. Friendly messages
/// for the two failure modes a user is most likely to hit (no image
/// on clipboard, no QR in the image); other arboard / decode errors
/// fall through with their underlying detail.
fn grab_clipboard_image_rows() -> Result<Vec<enroll::file::FileRowPreview>, String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("clipboard: {e}"))?;
    let img = cb.get_image().map_err(|e| match e {
        arboard::Error::ContentNotAvailable => {
            "Clipboard has no image. Take a screenshot of the QR (or copy an image), then try again."
                .to_string()
        }
        other => format!("clipboard image: {other}"),
    })?;
    let payloads = enroll::qr::decode_rgba(img.width as u32, img.height as u32, &img.bytes)
        .map_err(|e| match e {
            enroll::qr::QrError::NoCodesFound => {
                "No QR code found in the clipboard image.".to_string()
            }
            enroll::qr::QrError::QualityTooLow => {
                "QR code in the clipboard image is too low-quality to read.".to_string()
            }
            other => format!("QR decode: {other}"),
        })?;
    Ok(enroll::file::decode_payloads(payloads))
}

/// Translate the core `FileRowPreview` (file picker + clipboard +
/// future camera) into the Slint-shaped row model and tally the
/// status counts. `source_path` is "" for non-file sources;
/// destroy-source only fires when it's non-empty.
fn apply_decoded_rows(
    state: &AppState<'_>,
    source_path: String,
    rows: Vec<enroll::file::FileRowPreview>,
) {
    state.set_enroll_file_path(source_path.into());
    let mut valid = 0i32;
    let mut weak = 0i32;
    let mut errors = 0i32;
    let display_rows: Vec<FilePreviewRow> = rows
        .into_iter()
        .map(|r| {
            let error_str = r.error.map(|e| e.to_string()).unwrap_or_default();
            let weak_bits = r.weak_bits.unwrap_or(0) as i32;
            let payload = r.payload.unwrap_or_default();
            let is_error = !error_str.is_empty();
            let is_weak = !is_error && weak_bits > 0;
            if is_error {
                errors += 1;
            } else if is_weak {
                weak += 1;
            } else {
                valid += 1;
            }
            FilePreviewRow {
                issuer: r.issuer.unwrap_or_default().into(),
                account: r.account.unwrap_or_default().into(),
                weak_bits,
                error: error_str.into(),
                payload: payload.into(),
                // Default selection: strong+valid rows in. Weak rows
                // require an explicit checkbox click to opt in. Error
                // rows have no checkbox.
                selected: !is_error && !is_weak,
            }
        })
        .collect();
    state.set_enroll_file_rows(ModelRc::new(VecModel::from(display_rows)));
    state.set_enroll_file_valid(valid);
    state.set_enroll_file_weak(weak);
    state.set_enroll_file_error(errors);
}

fn clear_decoded_rows(state: &AppState<'_>, error_msg: String) {
    state.set_enroll_error(error_msg.into());
    state.set_enroll_file_path("".into());
    state.set_enroll_file_rows(empty_file_rows());
    state.set_enroll_file_valid(0);
    state.set_enroll_file_weak(0);
    state.set_enroll_file_error(0);
}

fn wire_save_enroll_file(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_save_enroll_file(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_enroll_error("".into());
        state.set_enroll_saving(true);

        let destroy_source = state.get_enroll_destroy_source();
        let source_path = state.get_enroll_file_path().to_string();
        let rows_model = state.get_enroll_file_rows();
        let mut payloads: Vec<(String, bool)> = Vec::new();
        for i in 0..rows_model.row_count() {
            if let Some(row) = rows_model.row_data(i) {
                if !row.selected || !row.error.is_empty() {
                    continue;
                }
                payloads.push((row.payload.to_string(), row.weak_bits > 0));
            }
        }

        let mut added = 0usize;
        let mut last_err: Option<String> = None;
        for (uri, is_weak) in payloads {
            let form = match enroll::parse::parse_otpauth_uri(&uri) {
                Ok(f) => f,
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            };
            // The user explicitly checked any weak row; honour their
            // opt-in by passing `force_weak=true` for those.
            match commit_form(&unlocked, form, is_weak) {
                Ok(()) => added += 1,
                Err(e) => last_err = Some(e.to_string()),
            }
        }

        state.set_enroll_saving(false);
        if added > 0 {
            // Best-effort source destruction — failures here don't
            // roll back the imports. `destroy_file` zero-fills then
            // unlinks; see issue #6 caveat about CoW / journals /
            // SSD wear leveling for limits.
            if destroy_source && !source_path.is_empty() {
                if let Err(e) = enroll::file::destroy_file(std::path::Path::new(&source_path)) {
                    eprintln!("destroy_file failed for {source_path}: {e}");
                }
            }
            // See note in `wire_save_enroll`: skip clear_enroll_state
            // here so we don't mutate enrollment properties while
            // EnrollmentPane is still rendered. Reset happens on the
            // next `on_open_enroll`.
            ui.global::<AppState>().set_mode(2);
            tick_codes(&ui, &unlocked);
        } else if let Some(msg) = last_err {
            state.set_enroll_error(format!("Nothing added. Last error: {msg}").into());
        } else {
            state.set_enroll_error("No rows selected — tick at least one row to import.".into());
        }
    });
}
