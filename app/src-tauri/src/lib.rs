// TODO(#6): consumers (Tauri commands + frontend wiring) land in
// follow-on commits on this branch. Allow dead-code while the layer
// is being built up.
#[allow(dead_code)]
mod enroll;
mod session;
mod store;
mod wizard;

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::SecretString;
use serde::Serialize;
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    LogicalPosition, Manager, Position, State,
};

use session::unlock::{self, UnlockErrorIpc};
use session::{EntryCode, Session};
use store::{NamedRecipient, Store, StoreError, StorePaths};

/// Tauri-managed global session.
///
/// `session` is None when the user hasn't unlocked (or has dismissed /
/// re-locked); Some after a successful unlock.
///
/// `generation` is a monotonic counter bumped every time the session is
/// dropped externally (`activate_window`, `hide_window`, `lock`,
/// `quit_app`). The `unlock` command captures the generation at start
/// and refuses to install the decrypted Session if the counter has
/// advanced since. Without this, a long-running unlock IPC could race
/// `activate_window`'s "fresh activation" gesture: the user clicks the
/// tray during the 15s touch wait, `activate_window` clears the state,
/// but the in-flight `unlock` still writes `Some(session)` afterward,
/// silently undoing the user's intent.
struct SessionInner {
    session: Option<Session>,
    generation: u64,
}

impl SessionInner {
    fn new() -> Self {
        Self {
            session: None,
            generation: 0,
        }
    }

    fn invalidate(&mut self) {
        self.session = None;
        self.generation = self.generation.wrapping_add(1);
    }
}

type SessionState = Mutex<SessionInner>;

#[derive(Serialize)]
struct EntrySummary {
    id: String,
    issuer: String,
    account: String,
}

#[derive(Serialize)]
struct UnlockResult {
    entries: Vec<EntrySummary>,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum CodesResponse {
    Locked,
    Codes { codes: Vec<EntryCode> },
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize)]
struct DecryptStoreResult {
    ok: bool,
    entries: usize,
    store_path: String,
    master_path: String,
    created: bool,
}

#[tauri::command]
fn is_initialized() -> Result<bool, String> {
    let paths = StorePaths::resolve().map_err(|e| e.to_string())?;
    Ok(paths.master.exists() && paths.store.exists())
}

#[tauri::command]
fn unlock(state: State<'_, SessionState>) -> Result<UnlockResult, UnlockErrorIpc> {
    let paths = StorePaths::resolve().map_err(|e| {
        eprintln!("unlock: paths failed: {e:#}");
        UnlockErrorIpc::Other {
            detail: "could not resolve storage paths".into(),
        }
    })?;

    // Capture the generation BEFORE the long decrypt. If the session
    // was invalidated mid-flight (e.g., user clicked tray to
    // re-activate during the touch wait), the counter advances and
    // we'll drop the just-decrypted Session at commit time rather
    // than silently undoing the user's intent.
    let gen_at_start = state.lock().unwrap().generation;

    let store_file = unlock::decrypt_store_with_yubikey(&paths).map_err(|e| {
        eprintln!("unlock failed: {e:#}");
        UnlockErrorIpc::from(&e)
    })?;

    let summaries: Vec<EntrySummary> = store_file
        .entries
        .iter()
        .filter(|e| matches!(e.kind, store::EntryKind::Totp))
        .map(|e| EntrySummary {
            id: e.id.clone(),
            issuer: e.issuer.clone(),
            account: e.account.clone(),
        })
        .collect();

    let session = Session::new(store_file.entries, now_unix());
    let mut inner = state.lock().unwrap();
    if inner.generation != gen_at_start {
        // Stale unlock — user re-activated during the touch wait.
        // Drop `session` (Entry's SecretString fields zeroize) and
        // surface as a touch timeout so the frontend re-prompts.
        eprintln!("unlock: stale (generation advanced); discarding decrypted session");
        return Err(UnlockErrorIpc::TouchTimeout);
    }
    inner.session = Some(session);

    Ok(UnlockResult { entries: summaries })
}

#[tauri::command]
fn get_codes(state: State<'_, SessionState>) -> Result<CodesResponse, String> {
    let mut guard = state.lock().unwrap();
    let now = now_unix();

    let should_relock = guard
        .session
        .as_ref()
        .map(|s| s.should_relock(now))
        .unwrap_or(true);
    if should_relock {
        guard.invalidate();
        return Ok(CodesResponse::Locked);
    }

    let session = guard.session.as_ref().unwrap();
    let codes = session.codes(now).map_err(|e| {
        eprintln!("get_codes failed: {e:#}");
        "could not generate codes".to_string()
    })?;
    Ok(CodesResponse::Codes { codes })
}

#[tauri::command]
fn lock(state: State<'_, SessionState>) -> Result<(), String> {
    state.lock().unwrap().invalidate();
    Ok(())
}

#[tauri::command]
fn hide_window(app: tauri::AppHandle, state: State<'_, SessionState>) -> Result<(), String> {
    state.lock().unwrap().invalidate();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    Ok(())
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle, state: State<'_, SessionState>) {
    // Drop the session before exit so seeds don't sit in RAM during
    // shutdown teardown.
    state.lock().unwrap().invalidate();
    app.exit(0);
}

#[derive(Serialize)]
struct FinalizeResult {
    store_path: String,
    master_path: String,
    config_path: String,
}

#[tauri::command]
fn finalize_init(passphrase: String, yubikey_recipient: String) -> Result<FinalizeResult, String> {
    // TODO(#13): passphrase arrives as String over IPC; same residue
    // concern as decrypt_store. Move into SecretString here and drop
    // the String at end of scope.
    let paths = StorePaths::resolve().map_err(|e| {
        eprintln!("finalize_init: paths failed: {e:#}");
        format!("could not resolve storage paths: {e}")
    })?;

    let recipient = wizard::yubikey::recipient_from_string(&yubikey_recipient).map_err(|e| {
        eprintln!("finalize_init: recipient parse failed: {e:#}");
        "YubiKey recipient is not a valid plugin recipient".to_string()
    })?;

    let secret = SecretString::from(passphrase);
    let named = NamedRecipient {
        bech32: yubikey_recipient.clone(),
        recipient,
    };
    Store::create(paths.clone(), secret, vec![named]).map_err(|e| {
        eprintln!("finalize_init: Store::create failed: {e:#}");
        user_facing(&e)
    })?;

    let config = wizard::config::Config {
        yubikey_recipient: Some(yubikey_recipient),
    };
    config.save(&paths.config).map_err(|e| {
        eprintln!("finalize_init: config save failed: {e:#}");
        format!("could not write config: {e}")
    })?;

    Ok(FinalizeResult {
        store_path: paths.store.display().to_string(),
        master_path: paths.master.display().to_string(),
        config_path: paths.config.display().to_string(),
    })
}

#[tauri::command]
fn detect_yubikey() -> Result<wizard::yubikey::DetectResult, String> {
    wizard::yubikey::detect().map_err(|e| {
        eprintln!("detect_yubikey failed: {e:#}");
        format!("could not detect YubiKey: {e}")
    })
}

#[tauri::command]
fn provision_yubikey(app: tauri::AppHandle) -> Result<wizard::yubikey::ProvisionResult, String> {
    wizard::yubikey::provision(&app).map_err(|e| {
        eprintln!("provision_yubikey failed: {e:#}");
        format!("YubiKey provisioning failed: {e}")
    })
}

#[tauri::command]
fn generate_passphrase() -> String {
    // TODO(#13): the SecretString is dropped at end of scope, but the
    // returned String crosses IPC and lives in the JS heap until the
    // user navigates past the passphrase pane. Wizard UX intentionally
    // disables click-to-copy to reduce clipboard exfiltration; the
    // heap residue itself is #13's concern.
    use age::secrecy::ExposeSecret;
    wizard::passphrase::generate(wizard::passphrase::DEFAULT_WORDS)
        .expose_secret()
        .to_string()
}

#[tauri::command]
fn decrypt_store(passphrase: String) -> Result<DecryptStoreResult, String> {
    // TODO(#13): passphrase arrives as a String from the IPC layer and
    // sits in the JS engine's heap before this point — full memory
    // hygiene needs work on both sides.
    let paths = StorePaths::resolve().map_err(|e| user_facing(&e.into()))?;
    let secret = SecretString::from(passphrase);
    let exists = paths.master.exists() && paths.store.exists();
    let store_result = if exists {
        Store::open_with_passphrase(paths, secret)
    } else {
        Store::create(paths, secret, Vec::new())
    };
    let store = store_result.map_err(|e| {
        eprintln!("decrypt_store failed: {e:#}");
        user_facing(&e)
    })?;
    Ok(DecryptStoreResult {
        ok: true,
        entries: store.entries().len(),
        store_path: store.paths().store.display().to_string(),
        master_path: store.paths().master.display().to_string(),
        created: !exists,
    })
}

/// Map StoreError to a small set of UI-safe reasons. Rich detail goes
/// to stderr; the JS layer only sees a coarse string. Avoids leaking
/// crypto internals or filesystem paths through error messages.
fn user_facing(err: &StoreError) -> String {
    match err {
        StoreError::Crypto(_) => "could not decrypt — wrong passphrase or corrupted store",
        StoreError::InvalidMaster(_) | StoreError::InvalidStorePayload(_) => {
            "store contents are corrupted"
        }
        StoreError::TomlDe(_) | StoreError::TomlSer(_) => "store contents are corrupted",
        StoreError::Atomic(_) | StoreError::Io(_) => "filesystem error",
        StoreError::Paths(_) => "could not resolve storage path",
    }
    .into()
}

/// Tray left-click: always activate. Show + focus + drop any active
/// session + tell the frontend to re-enter AWAITING_TOUCH. Tray click
/// is the "activate tocken" gesture; every click re-prompts for a
/// touch even if the window is already visible. Predictable security
/// model: if you clicked the tray, you're committing to a fresh
/// authentication.
fn activate_window(app: &tauri::AppHandle) {
    use tauri::Emitter;
    if let Some(window) = app.get_webview_window("main") {
        if let Some(state) = app.try_state::<SessionState>() {
            state.lock().unwrap().invalidate();
        }
        let _ = anchor_top_right(&window);
        let _ = window.show();
        let _ = window.set_focus();
        let _ = app.emit("window:shown", ());
    }
}

fn anchor_top_right(window: &tauri::WebviewWindow) -> tauri::Result<()> {
    if let Some(monitor) = window.current_monitor()? {
        let scale = monitor.scale_factor();
        let monitor_size = monitor.size();
        let win_size = window.outer_size()?;
        let x = (monitor_size.width as f64 - win_size.width as f64) / scale - 16.0;
        let y = 32.0;
        window.set_position(Position::Logical(LogicalPosition { x, y }))?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage::<SessionState>(Mutex::new(SessionInner::new()))
        .invoke_handler(tauri::generate_handler![
            decrypt_store,
            is_initialized,
            generate_passphrase,
            detect_yubikey,
            provision_yubikey,
            finalize_init,
            unlock,
            get_codes,
            lock,
            hide_window,
            quit_app
        ])
        .setup(|app| {
            // libayatana-appindicator (Tauri's tray backend on Linux)
            // is menu-centric: clicking a tray icon shows the menu, by
            // design. Without a menu attached the icon doesn't render
            // at all on most Wayland compositors. Compromise for v0:
            // single-item menu with "Activate". The menu still pops on
            // primary click, but it's a single-item menu so the user
            // is one click away from activation. See follow-up issue
            // for a structural fix (pure SNI / Plasmoid / etc.).
            // Quit lives inside the window — see quit_app command +
            // footer button — so the menu doesn't carry it.
            let activate_item = MenuItemBuilder::with_id("activate", "Activate").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&activate_item]).build()?;

            let _tray = TrayIconBuilder::with_id("tocken-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("tocken")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    if event.id().as_ref() == "activate" {
                        activate_window(app);
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        activate_window(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
