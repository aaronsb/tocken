//! Locked + unlocked code panel: unlock thread, 1Hz tick, actions
//! mode (multi-select + Remove with confirmation guard).

use std::collections::HashSet;
use std::thread;

use slint::{ComponentHandle, ModelRc, VecModel};
use tocken_core::session::{unlock, EntryCode, Session, LOCK_AFTER_ROTATIONS};
use tocken_core::store::StorePaths;

use crate::{now_unix, AppState, EntryRow, MainWindow, SharedUnlocked, Unlocked};

pub(crate) fn wire_unlock(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_unlock(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_unlocking(true);
        state.set_unlock_error("".into());

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
                let state = ui.global::<AppState>();
                state.set_unlocking(false);
                match outcome {
                    Ok(store) => {
                        let session = Session::new(store.entries().to_vec(), now_unix());
                        *unlocked_for_done.lock().unwrap() = Some(Unlocked {
                            store,
                            session,
                            selected_ids: HashSet::new(),
                        });
                        state.set_mode(2);
                        // Render codes immediately rather than waiting
                        // for the next 1Hz tick.
                        tick_codes(&ui, &unlocked_for_done);
                    }
                    Err(msg) => {
                        state.set_unlock_error(msg.into());
                    }
                }
            });
        });
    });
}

pub(crate) fn wire_lock(ui: &MainWindow, unlocked: SharedUnlocked) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_lock(move || {
        *unlocked.lock().unwrap() = None;
        if let Some(ui) = weak.upgrade() {
            let state = ui.global::<AppState>();
            state.set_mode(1);
            state.set_unlock_error("".into());
            state.set_entries(empty_entries());
            state.set_relock_seconds(0);
            state.set_actions_active(false);
            state.set_selected_count(0);
            state.set_confirming_remove(false);
            state.set_action_toast("".into());
        }
    });
}

pub(crate) fn tick_codes(ui: &MainWindow, unlocked: &SharedUnlocked) {
    let mut guard = unlocked.lock().unwrap();
    let Some(u) = guard.as_ref() else {
        return;
    };

    let state = ui.global::<AppState>();
    let now = now_unix();
    if u.session.should_relock(now) {
        *guard = None;
        drop(guard);
        state.set_mode(1);
        state.set_entries(empty_entries());
        state.set_relock_seconds(0);
        state.set_unlock_error("Session re-locked. Touch to unlock again.".into());
        return;
    }

    let codes = match u.session.codes(now) {
        Ok(c) => c,
        Err(_) => return,
    };
    let relock_seconds = seconds_until_relock(u.session.unlocked_at_unix(), &codes, now);

    let rows: Vec<EntryRow> = codes
        .into_iter()
        .map(|c| entry_row_from_code(c, &u.selected_ids))
        .collect();
    let selected_count = u.selected_ids.len() as i32;
    state.set_entries(ModelRc::new(VecModel::from(rows)));
    state.set_relock_seconds(relock_seconds as i32);
    state.set_selected_count(selected_count);
}

fn entry_row_from_code(c: EntryCode, selected_ids: &HashSet<String>) -> EntryRow {
    let selected = selected_ids.contains(&c.id);
    EntryRow {
        id: c.id.into(),
        issuer: c.issuer.into(),
        account: c.account.into(),
        code: format_code(&c.code).into(),
        digits: c.digits as i32,
        period: c.period as i32,
        time_remaining: c.time_remaining as i32,
        selected,
    }
}

fn empty_entries() -> ModelRc<EntryRow> {
    ModelRc::new(VecModel::from(Vec::<EntryRow>::new()))
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

/// Wires the Actions toggle and its CRUD callbacks.
///
/// Actions mode is a sub-state of `mode == 2`: per-entry checkboxes
/// appear and the bottom action bar swaps to Done / Remove / Update
/// / Comment. Selection state lives in `Unlocked.selected_ids` so
/// the 1Hz tick can rebuild the entry model without losing
/// selections; the Slint `EntryRow.selected` field is repopulated
/// every tick from the set.
///
/// Remove is implemented end-to-end with a confirmation pane.
/// Update / Comment are stubs that show a toast — full implementation
/// requires adding a `comment` field to the store schema (Update
/// also needs an edit form), tracked for the next session.
pub(crate) fn wire_actions(ui: &MainWindow, unlocked: SharedUnlocked) {
    {
        let weak = ui.as_weak();
        ui.global::<AppState>().on_enter_actions(move || {
            if let Some(ui) = weak.upgrade() {
                ui.global::<AppState>().set_actions_active(true);
                ui.global::<AppState>().set_action_toast("".into());
            }
        });
    }
    {
        let weak = ui.as_weak();
        let unlocked = unlocked.clone();
        ui.global::<AppState>().on_exit_actions(move || {
            if let Ok(mut guard) = unlocked.lock() {
                if let Some(u) = guard.as_mut() {
                    u.selected_ids.clear();
                }
            }
            if let Some(ui) = weak.upgrade() {
                let state = ui.global::<AppState>();
                state.set_actions_active(false);
                state.set_action_toast("".into());
                state.set_selected_count(0);
                tick_codes(&ui, &unlocked);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let unlocked = unlocked.clone();
        ui.global::<AppState>().on_toggle_entry_selected(move |id| {
            let id = id.to_string();
            {
                let mut guard = unlocked.lock().unwrap();
                let Some(u) = guard.as_mut() else {
                    return;
                };
                if u.selected_ids.contains(&id) {
                    u.selected_ids.remove(&id);
                } else {
                    u.selected_ids.insert(id);
                }
            }
            if let Some(ui) = weak.upgrade() {
                tick_codes(&ui, &unlocked);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let unlocked = unlocked.clone();
        ui.global::<AppState>().on_confirm_remove(move || {
            let outcome = remove_selected_and_save(&unlocked);
            if let Some(ui) = weak.upgrade() {
                let state = ui.global::<AppState>();
                match outcome {
                    Ok(removed) => {
                        state.set_action_toast(
                            format!(
                                "Removed {removed} {}.",
                                if removed == 1 { "entry" } else { "entries" }
                            )
                            .into(),
                        );
                    }
                    Err(msg) => {
                        state.set_action_toast(format!("Remove failed: {msg}").into());
                    }
                }
                tick_codes(&ui, &unlocked);
            }
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<AppState>().on_show_coming_soon(move |msg| {
            if let Some(ui) = weak.upgrade() {
                ui.global::<AppState>().set_action_toast(msg);
            }
        });
    }
}

/// Apply `Store::remove_entry` for every currently-selected ID, then
/// re-encrypt the store and rebuild the Session view. Mirrors the
/// commit pipeline used by enrollment (mutate Store → save → rebuild
/// Session preserving `unlocked_at_unix`).
fn remove_selected_and_save(unlocked: &SharedUnlocked) -> Result<usize, String> {
    let mut guard = unlocked.lock().unwrap();
    let Some(u) = guard.as_mut() else {
        return Err("session is locked".into());
    };
    if u.selected_ids.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = u.selected_ids.iter().cloned().collect();
    let mut removed = 0usize;
    for id in &ids {
        if u.store.remove_entry(id) {
            removed += 1;
        }
    }
    if removed == 0 {
        return Ok(0);
    }
    u.store.save().map_err(|e| format!("{e}"))?;
    u.selected_ids.clear();
    let unlocked_at = u.session.unlocked_at_unix();
    u.session = Session::new(u.store.entries().to_vec(), unlocked_at);
    Ok(removed)
}
