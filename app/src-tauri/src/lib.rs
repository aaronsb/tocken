use std::io::Write;
use std::process::{Command, Stdio};

use serde::Serialize;
use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    LogicalPosition, Manager, Position,
};

const SMOKE_TEST_PLAINTEXT: &[u8] = b"tocken: hardware-key flow OK";

#[derive(Serialize)]
struct TouchResult {
    ok: bool,
    message: String,
    serial: Option<String>,
    recipient: Option<String>,
}

#[tauri::command]
fn verify_touch() -> Result<TouchResult, String> {
    let identity = capture("age-plugin-yubikey", &["--identity"])
        .map_err(|e| format!("age-plugin-yubikey failed: {e}. Is the YubiKey plugged in?"))?;

    let recipient = parse_field(&identity, "Recipient:")
        .ok_or_else(|| "could not parse recipient from age-plugin-yubikey output".to_string())?;
    let serial = parse_field(&identity, "Serial:")
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string());

    let identity_file = tempfile::NamedTempFile::new()
        .map_err(|e| format!("tempfile: {e}"))?;
    std::fs::write(identity_file.path(), &identity)
        .map_err(|e| format!("write identity: {e}"))?;

    let ciphertext = pipe(
        "age",
        &["-r", &recipient],
        SMOKE_TEST_PLAINTEXT,
    )?;

    let plaintext = pipe(
        "age",
        &["-d", "-i", identity_file.path().to_str().unwrap()],
        &ciphertext,
    )
    .map_err(|e| format!("decrypt failed (no touch within timeout?): {e}"))?;

    if plaintext != SMOKE_TEST_PLAINTEXT {
        return Err(format!(
            "decrypted plaintext mismatch: got {:?}",
            String::from_utf8_lossy(&plaintext)
        ));
    }

    Ok(TouchResult {
        ok: true,
        message: "Touch verified — age round-trip succeeded.".into(),
        serial,
        recipient: Some(recipient),
    })
}

fn capture(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {cmd}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{cmd} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn pipe(cmd: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {cmd}: {e}"))?;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input)
        .map_err(|e| format!("write to {cmd} stdin: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("{cmd} wait: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{cmd} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn parse_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let trimmed = line.trim_start_matches('#').trim();
        trimmed.strip_prefix(key).map(|v| v.trim().to_string())
    })
}

fn toggle_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            let _ = anchor_top_right(&window);
            let _ = window.show();
            let _ = window.set_focus();
        }
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
        .invoke_handler(tauri::generate_handler![verify_touch])
        .setup(|app| {
            let show_item = MenuItemBuilder::with_id("show", "Show / hide").build(app)?;
            let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app)
                .items(&[&show_item, &quit_item])
                .build()?;

            let _tray = TrayIconBuilder::with_id("tocken-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("tocken")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => toggle_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_window(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
