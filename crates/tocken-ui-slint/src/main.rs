//! Slint front-end entry point. Stage 1 of the ADR-300 rebuild —
//! welcome pane that exercises the workspace ↔ Slint ↔ tocken-core
//! wiring by generating a Diceware passphrase and rendering it.

use secrecy::ExposeSecret;
use tocken_core::wizard;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let weak = ui.as_weak();
    ui.on_generate_passphrase(move || {
        let phrase = wizard::passphrase::generate(wizard::passphrase::DEFAULT_WORDS);
        if let Some(ui) = weak.upgrade() {
            ui.set_passphrase(phrase.expose_secret().into());
        }
    });

    ui.run()
}
