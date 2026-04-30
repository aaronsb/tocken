//! Slint front-end entry point.
//!
//! Stages 1-3 of the ADR-300 rebuild live here:
//!
//! - **Stage 1** (welcome + passphrase): proves the workspace ↔ Slint
//!   ↔ tocken-core wiring.
//! - **Stage 2** (full first-run wizard): passphrase → confirm →
//!   YubiKey detect → provision (with live log) → location → done.
//!   Long-running calls run on worker threads; UI updates marshal
//!   via `slint::invoke_from_event_loop`.
//! - **Stage 3** (unlock + code panel): if a store already exists,
//!   start in mode = locked. Unlock via `decrypt_store_with_yubikey`
//!   on a worker thread; on success, install a `Session` in shared
//!   state and switch to mode = unlocked. A 1Hz Slint Timer
//!   refreshes codes and triggers re-lock when
//!   `Session::should_relock` crosses the rotation threshold.
//!
//! Session state lives in `Arc<Mutex<Option<Session>>>` because the
//! unlock worker thread hands the freshly-decrypted Session back to
//! the UI thread via `invoke_from_event_loop`, whose closure must be
//! `Send`. `Rc<RefCell<…>>` would suffice for UI-only access but
//! cannot cross threads.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use slint::{ComponentHandle, ModelRc, VecModel};
use tocken_core::session::{unlock, EntryCode, Session, LOCK_AFTER_ROTATIONS};
use tocken_core::store::{NamedRecipient, Store, StorePaths};
use tocken_core::wizard;

slint::include_modules!();

type SharedSession = Arc<Mutex<Option<Session>>>;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;
    let session: SharedSession = Arc::new(Mutex::new(None));

    populate_paths_and_mode(&ui);
    wire_passphrase(&ui);
    wire_copy_passphrase(&ui);
    wire_detect(&ui);
    wire_provision(&ui);
    wire_finalize(&ui);
    wire_unlock(&ui, session.clone());
    wire_lock(&ui, session.clone());

    // 1Hz tick: refresh codes + check should_relock. Kept in scope
    // for the lifetime of `main`; dropping it stops the timer.
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    let session_for_timer = session.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            if let Some(ui) = weak.upgrade() {
                tick_codes(&ui, &session_for_timer);
            }
        },
    );

    ui.run()?;
    Ok(())
}

/// Set initial mode based on whether the encrypted store files
/// already exist on disk. If they do, jump straight to the locked
/// pane (mode = 1). Otherwise the wizard opens.
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

fn wire_unlock(ui: &MainWindow, session: SharedSession) {
    let weak = ui.as_weak();
    ui.on_unlock(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        ui.set_unlocking(true);
        ui.set_unlock_error("".into());

        let weak_done = weak.clone();
        let session_for_done = session.clone();
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
                        let new_session = Session::new(store.entries().to_vec(), now_unix());
                        *session_for_done.lock().unwrap() = Some(new_session);
                        ui.set_mode(2);
                        // Render codes immediately rather than waiting
                        // for the next 1Hz tick.
                        tick_codes(&ui, &session_for_done);
                    }
                    Err(msg) => {
                        ui.set_unlock_error(msg.into());
                    }
                }
            });
        });
    });
}

fn wire_lock(ui: &MainWindow, session: SharedSession) {
    let weak = ui.as_weak();
    ui.on_lock(move || {
        *session.lock().unwrap() = None;
        if let Some(ui) = weak.upgrade() {
            ui.set_mode(1);
            ui.set_unlock_error("".into());
            ui.set_entries(empty_entries());
            ui.set_relock_seconds(0);
        }
    });
}

/// 1Hz tick. Reads the shared Session under lock; if it's expired,
/// drops it and flips to the locked pane. Otherwise renders the
/// current codes and refreshes the global re-lock countdown.
fn tick_codes(ui: &MainWindow, session: &SharedSession) {
    let mut guard = session.lock().unwrap();
    let Some(s) = guard.as_ref() else {
        return;
    };

    let now = now_unix();
    if s.should_relock(now) {
        *guard = None;
        drop(guard);
        ui.set_mode(1);
        ui.set_entries(empty_entries());
        ui.set_relock_seconds(0);
        ui.set_unlock_error("Session re-locked. Touch to unlock again.".into());
        return;
    }

    let codes = match s.codes(now) {
        Ok(c) => c,
        Err(_) => {
            // Code generation failed — likely a malformed secret.
            // Nothing useful we can show; leave the previous render.
            return;
        }
    };

    let relock_seconds = seconds_until_relock(s.unlocked_at_unix(), &codes, now);

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

/// Pretty-print a TOTP code with a single-space midpoint split:
/// "123456" → "123 456", "12345678" → "1234 5678". Lengths outside
/// {6, 8} pass through unchanged.
fn format_code(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_owned(),
    }
}

/// Compute seconds until `Session::should_relock` will trigger. The
/// session re-locks once `min_rotations(now)` >= `LOCK_AFTER_ROTATIONS`.
/// `min_rotations` picks the entry with the *largest* period (slowest
/// rotator), since that produces the smallest rotation count. We
/// derive the exact unix-second when that entry will hit the
/// threshold.
fn seconds_until_relock(unlocked_at: u64, codes: &[EntryCode], now: u64) -> u64 {
    let Some(slowest_period) = codes.iter().map(|c| c.period as u64).max() else {
        // Empty session: Session::min_rotations returns 0 forever, so
        // there is no relock to count down to.
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
