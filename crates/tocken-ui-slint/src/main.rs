//! Slint front-end entry point. Stage 2 of the ADR-300 rebuild —
//! full first-run wizard wired against tocken-core. Long-running
//! backend calls (detect / provision / finalize) run on worker
//! threads; UI updates are marshaled back via
//! `slint::invoke_from_event_loop`. The provision callback (the new
//! `FnMut(&str)` shape introduced in the extraction commit) streams
//! plugin output line-by-line into the UI's provision-log property.

use std::thread;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use slint::ComponentHandle;
use tocken_core::store::{NamedRecipient, Store, StorePaths};
use tocken_core::wizard;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;

    populate_paths(&ui);
    wire_passphrase(&ui);
    wire_copy_passphrase(&ui);
    wire_detect(&ui);
    wire_provision(&ui);
    wire_finalize(&ui);

    ui.run()?;
    Ok(())
}

fn populate_paths(ui: &MainWindow) {
    if let Ok(paths) = StorePaths::resolve() {
        ui.set_store_path(paths.store.display().to_string().into());
        ui.set_master_path(paths.master.display().to_string().into());
        ui.set_config_path(paths.config.display().to_string().into());
        ui.set_store_already_exists(paths.master.exists() && paths.store.exists());
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
        let copied = arboard::Clipboard::new()
            .and_then(|mut cb| cb.set_text(phrase))
            .is_ok();
        if !copied {
            return;
        }
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
