//! Slint front-end entry point.
//!
//! Stages 1-4 of the ADR-300 rebuild live here:
//!
//! - **Stage 1** welcome + passphrase: workspace ↔ Slint ↔ tocken-core
//!   wiring.
//! - **Stage 2** first-run wizard: passphrase → confirm → YubiKey
//!   detect → provision → location → done. Long-running calls run on
//!   worker threads; UI updates marshal via `slint::invoke_from_event_loop`.
//! - **Stage 3** unlock + code panel: routes to the locked pane on
//!   startup if the store exists; 1Hz Slint Timer drives codes refresh
//!   and re-lock.
//! - **Stage 4** enrollment: paste-URI / manual / file picker. Single
//!   commit pipeline (normalize → vet → finalize → store.add_entry →
//!   store.save → rebuild Session). Weak-secret confirmation is a
//!   typed sub-mode flowing from `EnrollError::WeakSecret { bits }`.
//!
//! Unlocked state holds both the `Store` (for mutation + save) and
//! the `Session` view (for code generation). It lives in
//! `Arc<Mutex<Option<Unlocked>>>` because the unlock worker thread
//! hands the freshly-decrypted state back to the UI thread via
//! `invoke_from_event_loop`, whose closure must be `Send`.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use tocken_core::enroll::{self, EnrollError, EnrollForm};
use tocken_core::session::{unlock, EntryCode, Session, LOCK_AFTER_ROTATIONS};
use tocken_core::store::format::{Algorithm, Entry, EntryKind};
use tocken_core::store::{NamedRecipient, Store, StorePaths};
use tocken_core::wizard;

slint::include_modules!();

struct Unlocked {
    store: Store,
    session: Session,
}

type SharedUnlocked = Arc<Mutex<Option<Unlocked>>>;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;
    let unlocked: SharedUnlocked = Arc::new(Mutex::new(None));

    populate_paths_and_mode(&ui);
    wire_passphrase(&ui);
    wire_copy_passphrase(&ui);
    wire_detect(&ui);
    wire_provision(&ui);
    wire_finalize(&ui);
    wire_unlock(&ui, unlocked.clone());
    wire_lock(&ui, unlocked.clone());
    wire_enroll(&ui, unlocked.clone());

    // 1Hz tick: refresh codes + check should_relock. Kept in scope
    // for the lifetime of `main`; dropping it stops the timer.
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    let unlocked_for_timer = unlocked.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(ui) = weak.upgrade() {
                tick_codes(&ui, &unlocked_for_timer);
            }
        },
    );

    ui.run()?;
    Ok(())
}

fn populate_paths_and_mode(ui: &MainWindow) {
    let Ok(paths) = StorePaths::resolve() else {
        return;
    };
    ui.set_store_path(paths.store.display().to_string().into());
    ui.set_master_path(paths.master.display().to_string().into());
    ui.set_config_path(paths.config.display().to_string().into());
    if paths.master.exists() && paths.store.exists() {
        ui.set_mode(1);
    } else {
        ui.set_mode(0);
    }
}

fn wire_passphrase(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_generate_passphrase(move || {
        let phrase = wizard::passphrase::generate(wizard::passphrase::DEFAULT_WORDS);
        if let Some(ui) = weak.upgrade() {
            ui.set_passphrase(phrase.expose_secret().into());
        }
    });
}

fn wire_copy_passphrase(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_copy_passphrase(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let phrase = ui.get_passphrase().to_string();
        if phrase.is_empty() {
            return;
        }

        // On Linux X11/Wayland the clipboard contents are owned by
        // the writing process; dropping the `Clipboard` handle
        // releases ownership immediately, often before a clipboard
        // manager or paste consumer can fetch the bytes. arboard's
        // `SetExtLinux::wait()` runs the selection loop on the
        // calling thread until ownership is transferred — so we hand
        // it a dedicated thread to block on. On non-Linux platforms
        // `set_text` is synchronous and persistent; the cfg gate
        // keeps this from breaking macOS / Windows builds.
        std::thread::spawn(move || {
            let Ok(mut cb) = arboard::Clipboard::new() else {
                return;
            };
            #[cfg(target_os = "linux")]
            {
                use arboard::SetExtLinux;
                let _ = cb.set().wait().text(phrase);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = cb.set_text(phrase);
            }
        });

        ui.set_passphrase_copied(true);
        let weak_reset = weak.clone();
        slint::Timer::single_shot(Duration::from_secs(2), move || {
            if let Some(ui) = weak_reset.upgrade() {
                ui.set_passphrase_copied(false);
            }
        });
    });
}

fn wire_detect(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_detect_yubikey(move || {
        let weak = weak.clone();
        thread::spawn(move || {
            let result = wizard::yubikey::detect();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                match result {
                    Ok(detect) => {
                        ui.set_yubikey_configured(detect.configured);
                        ui.set_yubikey_recipient(detect.recipient.unwrap_or_default().into());
                        ui.set_yubikey_serial(detect.serial.unwrap_or_default().into());
                        ui.set_yubikey_error("".into());
                    }
                    Err(e) => {
                        ui.set_yubikey_error(format!("Detect failed: {e}").into());
                    }
                }
                ui.set_yubikey_detected(true);
            });
        });
    });
}

fn wire_provision(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_provision_yubikey(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_provision_in_progress(true);
            ui.set_provision_log("".into());
            ui.set_yubikey_error("".into());
        }

        let weak_lines = weak.clone();
        let weak_done = weak.clone();
        thread::spawn(move || {
            let result = wizard::yubikey::provision(move |line| {
                let line = line.to_string();
                let weak = weak_lines.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        let mut log = ui.get_provision_log().to_string();
                        log.push_str(&line);
                        log.push('\n');
                        ui.set_provision_log(log.into());
                    }
                });
            });

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                ui.set_provision_in_progress(false);
                match result {
                    Ok(r) => {
                        ui.set_yubikey_recipient(r.recipient.into());
                        ui.set_pin_puk_message(r.pin_puk_message.unwrap_or_default().into());
                    }
                    Err(e) => {
                        ui.set_yubikey_error(format!("Provisioning failed: {e}").into());
                    }
                }
            });
        });
    });
}

fn wire_finalize(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.on_finalize(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_finalize_in_progress(true);
        ui.set_finalize_error("".into());

        let passphrase = ui.get_passphrase().to_string();
        let recipient_str = ui.get_yubikey_recipient().to_string();
        let weak_done = weak.clone();

        thread::spawn(move || {
            let outcome = create_store(&passphrase, &recipient_str);

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                ui.set_finalize_in_progress(false);
                match outcome {
                    Ok(()) => ui.set_step(5),
                    Err(e) => ui.set_finalize_error(e.into()),
                }
            });
        });
    });
}

fn create_store(passphrase: &str, recipient_str: &str) -> Result<(), String> {
    let paths = StorePaths::resolve().map_err(|e| format!("paths: {e}"))?;
    let recipient = wizard::yubikey::recipient_from_string(recipient_str)
        .map_err(|e| format!("recipient: {e}"))?;
    let secret = SecretString::from(passphrase.to_owned());
    let named = NamedRecipient {
        bech32: recipient_str.to_owned(),
        recipient,
    };
    Store::create(paths.clone(), secret, vec![named]).map_err(|e| format!("store: {e}"))?;

    let cfg = wizard::config::Config {
        yubikey_recipient: Some(recipient_str.to_owned()),
    };
    cfg.save(&paths.config)
        .map_err(|e| format!("config: {e}"))?;
    Ok(())
}

fn wire_unlock(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.on_unlock(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_unlocking(true);
        ui.set_unlock_error("".into());

        let weak_done = weak.clone();
        let unlocked_for_done = unlocked.clone();
        thread::spawn(move || {
            let outcome = match StorePaths::resolve() {
                Ok(paths) => {
                    unlock::decrypt_store_with_yubikey(&paths).map_err(|e| format_unlock_error(&e))
                }
                Err(e) => Err(format!("paths: {e}")),
            };

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                ui.set_unlocking(false);
                match outcome {
                    Ok(store) => {
                        let session = Session::new(store.entries().to_vec(), now_unix());
                        *unlocked_for_done.lock().unwrap() = Some(Unlocked { store, session });
                        ui.set_mode(2);
                        // Render codes immediately rather than waiting
                        // for the next 1Hz tick.
                        tick_codes(&ui, &unlocked_for_done);
                    }
                    Err(msg) => {
                        ui.set_unlock_error(msg.into());
                    }
                }
            });
        });
    });
}

fn wire_lock(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.on_lock(move || {
        *unlocked.lock().unwrap() = None;
        if let Some(ui) = weak.upgrade() {
            ui.set_mode(1);
            ui.set_unlock_error("".into());
            ui.set_entries(empty_entries());
            ui.set_relock_seconds(0);
        }
    });
}

fn tick_codes(ui: &MainWindow, unlocked: &SharedUnlocked) {
    let mut guard = unlocked.lock().unwrap();
    let Some(u) = guard.as_ref() else {
        return;
    };

    let now = now_unix();
    if u.session.should_relock(now) {
        *guard = None;
        drop(guard);
        ui.set_mode(1);
        ui.set_entries(empty_entries());
        ui.set_relock_seconds(0);
        ui.set_unlock_error("Session re-locked. Touch to unlock again.".into());
        return;
    }

    let codes = match u.session.codes(now) {
        Ok(c) => c,
        Err(_) => return,
    };
    let relock_seconds = seconds_until_relock(u.session.unlocked_at_unix(), &codes, now);

    let rows: Vec<EntryRow> = codes.into_iter().map(entry_row_from_code).collect();
    ui.set_entries(ModelRc::new(VecModel::from(rows)));
    ui.set_relock_seconds(relock_seconds as i32);
}

fn entry_row_from_code(c: EntryCode) -> EntryRow {
    EntryRow {
        id: c.id.into(),
        issuer: c.issuer.into(),
        account: c.account.into(),
        code: format_code(&c.code).into(),
        period: c.period as i32,
        time_remaining: c.time_remaining as i32,
    }
}

fn empty_entries() -> ModelRc<EntryRow> {
    ModelRc::new(VecModel::from(Vec::<EntryRow>::new()))
}

fn empty_file_rows() -> ModelRc<FilePreviewRow> {
    ModelRc::new(VecModel::from(Vec::<FilePreviewRow>::new()))
}

fn format_code(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_owned(),
    }
}

fn seconds_until_relock(unlocked_at: u64, codes: &[EntryCode], now: u64) -> u64 {
    let Some(slowest_period) = codes.iter().map(|c| c.period as u64).max() else {
        return 0;
    };
    if slowest_period == 0 {
        return 0;
    }
    let unlock_step = unlocked_at / slowest_period;
    let target_unix = (unlock_step + LOCK_AFTER_ROTATIONS as u64) * slowest_period;
    target_unix.saturating_sub(now)
}

fn format_unlock_error(err: &unlock::UnlockError) -> String {
    use unlock::UnlockError::*;
    match err {
        PluginMissing => "age-plugin-yubikey is not installed.".into(),
        NoIdentity => "No YubiKey identity configured. Re-run the wizard.".into(),
        TouchTimeoutOrMismatch => "Touch not detected (timed out, or wrong YubiKey).".into(),
        StoreUnreadable(d) => format!("Store unreadable: {d}"),
        StoreCorrupted => "Store contents are corrupted.".into(),
        RecipientsMetadata(d) => format!("Recipients metadata: {d}"),
        Other(d) => format!("Unexpected: {d}"),
    }
}

// ---------- enrollment ----------

fn wire_enroll(ui: &MainWindow, unlocked: SharedUnlocked) {
    {
        let weak = ui.as_weak();
        ui.on_open_enroll(move || {
            if let Some(ui) = weak.upgrade() {
                clear_enroll_state(&ui);
                ui.set_mode(3);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_cancel_enroll(move || {
            if let Some(ui) = weak.upgrade() {
                clear_enroll_state(&ui);
                ui.set_mode(2);
            }
        });
    }
    wire_save_enroll(ui, unlocked.clone(), false);
    wire_save_enroll(ui, unlocked.clone(), true);
    wire_choose_enroll_file(ui);
    wire_save_enroll_file(ui, unlocked);
}

fn clear_enroll_state(ui: &MainWindow) {
    ui.set_enroll_source(0);
    ui.set_enroll_uri("".into());
    ui.set_enroll_issuer("".into());
    ui.set_enroll_account("".into());
    ui.set_enroll_secret("".into());
    ui.set_enroll_error("".into());
    ui.set_enroll_weak_prompt(false);
    ui.set_enroll_weak_bits(0);
    ui.set_enroll_saving(false);
    ui.set_enroll_file_path("".into());
    ui.set_enroll_file_loading(false);
    ui.set_enroll_file_rows(empty_file_rows());
    ui.set_enroll_file_valid(0);
    ui.set_enroll_file_weak(0);
    ui.set_enroll_file_error(0);
    ui.set_enroll_file_force_weak(false);
}

/// Wire either `on_save_enroll` (force_weak=false) or
/// `on_save_enroll_force` (force_weak=true). Both share a body —
/// only the flag passed to `vet_form` differs.
fn wire_save_enroll(ui: &MainWindow, unlocked: SharedUnlocked, force_weak: bool) {
    let weak = ui.as_weak();
    let unlocked = unlocked.clone();
    let handler = move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_enroll_error("".into());
        ui.set_enroll_saving(true);

        let form_result = match ui.get_enroll_source() {
            0 => parse_paste_form(&ui),
            1 => Ok(build_manual_form(&ui)),
            other => Err(EnrollError::InvalidUri {
                detail: format!("unknown source {other}"),
            }),
        };

        let form = match form_result {
            Ok(f) => f,
            Err(e) => {
                ui.set_enroll_saving(false);
                ui.set_enroll_error(e.to_string().into());
                return;
            }
        };

        match commit_form(&unlocked, form, force_weak) {
            Ok(()) => {
                clear_enroll_state(&ui);
                ui.set_mode(2);
                tick_codes(&ui, &unlocked);
            }
            Err(EnrollError::WeakSecret { bits }) => {
                ui.set_enroll_saving(false);
                ui.set_enroll_weak_bits(bits as i32);
                ui.set_enroll_weak_prompt(true);
            }
            Err(e) => {
                ui.set_enroll_saving(false);
                ui.set_enroll_error(e.to_string().into());
            }
        }
    };
    if force_weak {
        ui.on_save_enroll_force(handler);
    } else {
        ui.on_save_enroll(handler);
    }
}

fn parse_paste_form(ui: &MainWindow) -> Result<EnrollForm, EnrollError> {
    let uri = ui.get_enroll_uri().to_string();
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(EnrollError::InvalidUri {
            detail: "no URI entered".into(),
        });
    }
    enroll::parse::parse_otpauth_uri(trimmed)
}

fn build_manual_form(ui: &MainWindow) -> EnrollForm {
    EnrollForm {
        issuer: ui.get_enroll_issuer().to_string(),
        account: ui.get_enroll_account().to_string(),
        secret: SecretString::from(ui.get_enroll_secret().to_string()),
        digits: 6,
        period: 30,
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
    ui.on_choose_enroll_file(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_enroll_file_loading(true);
        ui.set_enroll_error("".into());

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
                ui.set_enroll_file_loading(false);
                match outcome {
                    Ok((path, rows)) => {
                        ui.set_enroll_file_path(path.into());
                        let mut valid = 0;
                        let mut weak = 0;
                        let mut errors = 0;
                        let display_rows: Vec<FilePreviewRow> = rows
                            .into_iter()
                            .map(|r| {
                                let error = r.error.map(|e| e.to_string()).unwrap_or_default();
                                let weak_bits = r.weak_bits.unwrap_or(0) as i32;
                                let payload = r.payload.unwrap_or_default();
                                if !error.is_empty() {
                                    errors += 1;
                                } else if weak_bits > 0 {
                                    weak += 1;
                                } else {
                                    valid += 1;
                                }
                                FilePreviewRow {
                                    issuer: r.issuer.unwrap_or_default().into(),
                                    account: r.account.unwrap_or_default().into(),
                                    weak_bits,
                                    error: error.into(),
                                    payload: payload.into(),
                                }
                            })
                            .collect();
                        ui.set_enroll_file_rows(ModelRc::new(VecModel::from(display_rows)));
                        ui.set_enroll_file_valid(valid);
                        ui.set_enroll_file_weak(weak);
                        ui.set_enroll_file_error(errors);
                    }
                    Err(msg) => {
                        ui.set_enroll_error(msg.into());
                        ui.set_enroll_file_rows(empty_file_rows());
                        ui.set_enroll_file_valid(0);
                        ui.set_enroll_file_weak(0);
                        ui.set_enroll_file_error(0);
                    }
                }
            });
        });
    });
}

fn wire_save_enroll_file(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.on_save_enroll_file(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_enroll_error("".into());
        ui.set_enroll_saving(true);

        // Snapshot the rows and the force-weak toggle off the UI so we
        // don't borrow the model across the commit loop.
        let force_weak = ui.get_enroll_file_force_weak();
        let rows_model = ui.get_enroll_file_rows();
        let mut payloads: Vec<(String, bool)> = Vec::new();
        for i in 0..rows_model.row_count() {
            if let Some(row) = rows_model.row_data(i) {
                if !row.error.is_empty() {
                    continue;
                }
                let is_weak = row.weak_bits > 0;
                if is_weak && !force_weak {
                    continue;
                }
                payloads.push((row.payload.to_string(), is_weak));
            }
        }

        let mut added = 0usize;
        let mut skipped = 0usize;
        let mut last_err: Option<String> = None;
        for (uri, is_weak) in payloads {
            let form = match enroll::parse::parse_otpauth_uri(&uri) {
                Ok(f) => f,
                Err(e) => {
                    skipped += 1;
                    last_err = Some(e.to_string());
                    continue;
                }
            };
            // For weak rows the user already opted in via the toggle.
            match commit_form(&unlocked, form, is_weak) {
                Ok(()) => added += 1,
                Err(e) => {
                    skipped += 1;
                    last_err = Some(e.to_string());
                }
            }
        }

        ui.set_enroll_saving(false);
        if added > 0 {
            clear_enroll_state(&ui);
            ui.set_mode(2);
            tick_codes(&ui, &unlocked);
        } else if let Some(msg) = last_err {
            ui.set_enroll_error(format!("Nothing added. Last error: {msg}").into());
        } else {
            ui.set_enroll_error("Nothing to add — pick a file first.".into());
        }
        // skipped count is not surfaced for now; if it becomes useful
        // we can wire a status line in stage 5+ alongside the
        // image-source UX work.
        let _ = skipped;
    });
}
