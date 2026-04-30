//! Slint front-end entry point.
//!
//! Stages 1-4 of the ADR-300 rebuild live across this crate:
//!
//! - **Stage 1** welcome + passphrase: workspace ↔ Slint ↔ tocken-core
//!   wiring.
//! - **Stage 2** first-run wizard: passphrase → confirm → YubiKey
//!   detect → provision → location → done. Long-running calls run on
//!   worker threads; UI updates marshal via
//!   `slint::invoke_from_event_loop`.
//! - **Stage 3** unlock + code panel: routes to the locked pane on
//!   startup if the store exists; 1Hz Slint Timer drives codes
//!   refresh and re-lock.
//! - **Stage 4** enrollment: paste-URI / manual / file picker. Single
//!   commit pipeline (normalize → vet → finalize → store.add_entry →
//!   store.save → rebuild Session). Weak-secret confirmation is a
//!   typed sub-mode flowing from `EnrollError::WeakSecret { bits }`.
//!
//! Per-pane wiring lives in `wizard.rs`, `enroll.rs`, and
//! `code_panel.rs`. This file owns the shared state types
//! (`Unlocked`, `SharedUnlocked`), the boot sequence, and the 1Hz
//! tick that drives both code refresh and re-lock.
//!
//! Unlocked state holds both the `Store` (for mutation + save) and
//! the `Session` view (for code generation). It lives in
//! `Arc<Mutex<Option<Unlocked>>>` because the unlock worker thread
//! hands the freshly-decrypted state back to the UI thread via
//! `invoke_from_event_loop`, whose closure must be `Send`.
//!
//! UI state lives in a Slint `global AppState` defined in
//! `ui/state.slint`. Rust callers access it via
//! `ui.global::<AppState>()` for setters / getters / `on_*` callback
//! wiring; this keeps `main.slint` thin and lets each pane component
//! (`wizard.slint`, `enrollment.slint`) read from the same surface
//! without per-property pass-through bindings.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use slint::ComponentHandle;
use tocken_core::session::Session;
use tocken_core::store::{Store, StorePaths};

mod code_panel;
mod enroll;
mod wizard;

slint::include_modules!();

pub(crate) struct Unlocked {
    pub(crate) store: Store,
    pub(crate) session: Session,
    /// Entry IDs currently checked in Actions mode. Lives on the
    /// Rust side so the 1Hz `tick_codes` rebuild can reconstruct
    /// `EntryRow.selected` without losing the user's selection.
    /// Cleared on lock and on `exit-actions`.
    pub(crate) selected_ids: HashSet<String>,
}

pub(crate) type SharedUnlocked = Arc<Mutex<Option<Unlocked>>>;

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;
    let unlocked: SharedUnlocked = Arc::new(Mutex::new(None));

    populate_paths_and_mode(&ui);
    wizard::wire_passphrase(&ui);
    wizard::wire_copy_passphrase(&ui);
    wizard::wire_detect(&ui);
    wizard::wire_provision(&ui);
    wizard::wire_finalize(&ui);
    code_panel::wire_unlock(&ui, unlocked.clone());
    code_panel::wire_lock(&ui, unlocked.clone());
    enroll::wire_enroll(&ui, unlocked.clone());
    code_panel::wire_actions(&ui, unlocked.clone());

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
                code_panel::tick_codes(&ui, &unlocked_for_timer);
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
    let state = ui.global::<AppState>();
    state.set_store_path(paths.store.display().to_string().into());
    state.set_master_path(paths.master.display().to_string().into());
    state.set_config_path(paths.config.display().to_string().into());
    if paths.master.exists() && paths.store.exists() {
        state.set_mode(1);
    } else {
        state.set_mode(0);
    }
}
