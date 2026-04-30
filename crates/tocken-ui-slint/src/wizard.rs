//! First-run wizard wiring: passphrase generation/copy, YubiKey
//! detection + provisioning, finalize → store creation.

use std::thread;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use slint::ComponentHandle;
use tocken_core::store::{NamedRecipient, Store, StorePaths};
use tocken_core::wizard;

use crate::{AppState, MainWindow};

pub(crate) fn wire_passphrase(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_generate_passphrase(move || {
        let phrase = wizard::passphrase::generate(wizard::passphrase::DEFAULT_WORDS);
        if let Some(ui) = weak.upgrade() {
            ui.global::<AppState>()
                .set_passphrase(phrase.expose_secret().into());
        }
    });
}

pub(crate) fn wire_copy_passphrase(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_copy_passphrase(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        let phrase = state.get_passphrase().to_string();
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

        state.set_passphrase_copied(true);
        let weak_reset = weak.clone();
        slint::Timer::single_shot(Duration::from_secs(2), move || {
            if let Some(ui) = weak_reset.upgrade() {
                ui.global::<AppState>().set_passphrase_copied(false);
            }
        });
    });
}

pub(crate) fn wire_detect(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_detect_yubikey(move || {
        let weak = weak.clone();
        thread::spawn(move || {
            let result = wizard::yubikey::detect();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                let state = ui.global::<AppState>();
                match result {
                    Ok(detect) => {
                        state.set_yubikey_configured(detect.configured);
                        state.set_yubikey_recipient(detect.recipient.unwrap_or_default().into());
                        state.set_yubikey_serial(detect.serial.unwrap_or_default().into());
                        state.set_yubikey_error("".into());
                    }
                    Err(e) => {
                        state.set_yubikey_error(format!("Detect failed: {e}").into());
                    }
                }
                state.set_yubikey_detected(true);
            });
        });
    });
}

pub(crate) fn wire_provision(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_provision_yubikey(move || {
        if let Some(ui) = weak.upgrade() {
            let state = ui.global::<AppState>();
            state.set_provision_in_progress(true);
            state.set_provision_log("".into());
            state.set_yubikey_error("".into());
        }

        let weak_lines = weak.clone();
        let weak_done = weak.clone();
        thread::spawn(move || {
            let result = wizard::yubikey::provision(move |line| {
                let line = line.to_string();
                let weak = weak_lines.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak.upgrade() {
                        let state = ui.global::<AppState>();
                        let mut log = state.get_provision_log().to_string();
                        log.push_str(&line);
                        log.push('\n');
                        state.set_provision_log(log.into());
                    }
                });
            });

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                let state = ui.global::<AppState>();
                state.set_provision_in_progress(false);
                match result {
                    Ok(r) => {
                        state.set_yubikey_recipient(r.recipient.into());
                        state.set_pin_puk_message(r.pin_puk_message.unwrap_or_default().into());
                    }
                    Err(e) => {
                        state.set_yubikey_error(format!("Provisioning failed: {e}").into());
                    }
                }
            });
        });
    });
}

pub(crate) fn wire_finalize(ui: &MainWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_finalize(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_finalize_in_progress(true);
        state.set_finalize_error("".into());

        let passphrase = state.get_passphrase().to_string();
        let recipient_str = state.get_yubikey_recipient().to_string();
        let weak_done = weak.clone();

        thread::spawn(move || {
            let outcome = create_store(&passphrase, &recipient_str);

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = weak_done.upgrade() else {
                    return;
                };
                let state = ui.global::<AppState>();
                state.set_finalize_in_progress(false);
                match outcome {
                    Ok(()) => state.set_step(5),
                    Err(e) => state.set_finalize_error(e.into()),
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
