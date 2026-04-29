//! YubiKey detection + provisioning via the `age-plugin-yubikey`
//! subprocess. ADR-100 §1 keeps plaintext seed material inside our
//! process, but the plugin protocol *requires* spawning the plugin
//! binary — and that subprocess only ever sees wrapped keys, never
//! plaintext, so the residue concern doesn't apply.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

const PLUGIN_BINARY: &str = "age-plugin-yubikey";

/// Result of probing for an already-provisioned YubiKey identity.
#[derive(Debug, Serialize)]
pub struct DetectResult {
    pub configured: bool,
    pub recipient: Option<String>,
    pub serial: Option<String>,
}

/// Result of running the provisioning subprocess to completion.
#[derive(Debug, Serialize)]
pub struct ProvisionResult {
    pub recipient: String,
    /// Some plugin runs migrate the YubiKey from default PIN/PUK and
    /// emit the new values. We surface them so the user can write
    /// them down (they're only needed for PIV admin operations).
    pub pin_puk_message: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("could not spawn {PLUGIN_BINARY}: {0}")]
    Spawn(std::io::Error),
    #[error("{PLUGIN_BINARY} exited with status {status}: {stderr}")]
    NonZero { status: i32, stderr: String },
    #[error("could not parse recipient from {PLUGIN_BINARY} output")]
    NoRecipient,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("emit: {0}")]
    Emit(#[from] tauri::Error),
}

/// Run `age-plugin-yubikey --identity`. If the YubiKey already has an
/// age slot configured, returns `configured: true` plus the recipient
/// and serial. If no identity is found (plugin returns non-zero or
/// stdout is empty), returns `configured: false` with no error — the
/// wizard treats that as "show the provisioning pane".
pub fn detect() -> Result<DetectResult, PluginError> {
    let output = Command::new(PLUGIN_BINARY)
        .arg("--identity")
        .output()
        .map_err(PluginError::Spawn)?;

    if !output.status.success() {
        // Treat as "not configured" rather than an error — the most
        // common reason for failure here is "no slot provisioned yet"
        // which is exactly what the wizard wants to handle.
        return Ok(DetectResult {
            configured: false,
            recipient: None,
            serial: None,
        });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let recipient = parse_field(&text, "Recipient:");
    let serial = parse_field(&text, "Serial:")
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string());

    Ok(DetectResult {
        configured: recipient.is_some(),
        recipient,
        serial,
    })
}

/// Spawn `age-plugin-yubikey --generate --touch-policy always
/// --pin-policy never --slot 1` and stream its stdout/stderr to the
/// frontend via the `wizard:provision-output` event so the user sees
/// progress live ("Generating key...", "Touch your YubiKey").
pub fn provision(app: &AppHandle) -> Result<ProvisionResult, PluginError> {
    let mut child = Command::new(PLUGIN_BINARY)
        .args([
            "--generate",
            "--touch-policy",
            "always",
            "--pin-policy",
            "never",
            "--slot",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(PluginError::Spawn)?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    // Collect everything into one transcript for parsing after exit;
    // simultaneously emit each line so the frontend can render it.
    let mut transcript = String::new();
    let app_handle = app.clone();

    // We could read stdout and stderr concurrently with threads, but
    // age-plugin-yubikey writes its progress messages mostly to one
    // channel at a time; sequential read keeps this simple. If output
    // ordering ever matters we'll revisit.
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        emit_line(&app_handle, &line)?;
        transcript.push_str(&line);
        transcript.push('\n');
    }
    let mut stderr_buf = String::new();
    for line in BufReader::new(stderr).lines() {
        let line = line?;
        emit_line(&app_handle, &line)?;
        stderr_buf.push_str(&line);
        stderr_buf.push('\n');
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(PluginError::NonZero {
            status: status.code().unwrap_or(-1),
            stderr: stderr_buf,
        });
    }

    let recipient = parse_field(&transcript, "Recipient:").ok_or(PluginError::NoRecipient)?;
    let pin_puk_message = extract_pin_puk(&transcript);

    Ok(ProvisionResult {
        recipient,
        pin_puk_message,
    })
}

fn emit_line(app: &AppHandle, line: &str) -> Result<(), tauri::Error> {
    app.emit("wizard:provision-output", line)
}

/// Pull a `Key: value` line out of plugin output, accepting an
/// optional `#` comment prefix.
fn parse_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let trimmed = line.trim_start_matches('#').trim();
        trimmed.strip_prefix(key).map(|v| v.trim().to_string())
    })
}

/// If the plugin output mentions PIN/PUK migration, capture the
/// surrounding context so the wizard can surface it. age-plugin-yubikey
/// prints something like "PIN: 12345678" alongside generation; we
/// keep the matched line(s) verbatim and let the UI render them.
fn extract_pin_puk(text: &str) -> Option<String> {
    let mut hits: Vec<&str> = text
        .lines()
        .filter(|line| {
            let l = line.to_lowercase();
            l.contains("pin:") || l.contains("puk:") || l.contains("management key")
        })
        .collect();
    hits.dedup();
    if hits.is_empty() {
        None
    } else {
        Some(hits.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_strips_comment_prefix_and_whitespace() {
        let text = "\
#       Serial: 1234567, Slot: 1
#    Recipient: age1yubikey1abc...
        ";
        assert_eq!(
            parse_field(text, "Recipient:"),
            Some("age1yubikey1abc...".into())
        );
        assert_eq!(
            parse_field(text, "Serial:"),
            Some("1234567, Slot: 1".into())
        );
    }

    #[test]
    fn parse_field_returns_none_when_missing() {
        assert!(parse_field("nothing here", "Recipient:").is_none());
    }

    #[test]
    fn extract_pin_puk_finds_canonical_lines() {
        let text = "Generating new key...\n\
                    PIN: 12345678\n\
                    PUK: 87654321\n\
                    Recipient: age1yubikey1xyz\n";
        let extracted = extract_pin_puk(text).unwrap();
        assert!(extracted.contains("PIN: 12345678"));
        assert!(extracted.contains("PUK: 87654321"));
    }

    #[test]
    fn extract_pin_puk_returns_none_when_absent() {
        assert!(extract_pin_puk("Recipient: age1yubikey1xyz\n").is_none());
    }

    /// Spike (task #19): proves the `age::plugin::RecipientPluginV1`
    /// integration round-trips against a real YubiKey provisioned with
    /// `age-plugin-yubikey`. Encrypt-only — wizard never decrypts.
    ///
    /// Requires hardware. Run with: `make test-hw`.
    #[test]
    #[ignore = "requires a YubiKey with age-plugin-yubikey provisioned"]
    fn plugin_recipient_round_trip() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::str::FromStr;

        use age::plugin::{Recipient as PluginRecipient, RecipientPluginV1};
        use age::{Encryptor, NoCallbacks};

        let identity_output = Command::new("age-plugin-yubikey")
            .arg("--identity")
            .output()
            .expect("age-plugin-yubikey --identity must run; is the plugin in PATH?");
        assert!(
            identity_output.status.success(),
            "age-plugin-yubikey --identity failed: {}",
            String::from_utf8_lossy(&identity_output.stderr)
        );
        let identity_text = String::from_utf8(identity_output.stdout).unwrap();

        let recipient_str = parse_field(&identity_text, "Recipient:")
            .expect("no Recipient: line in age-plugin-yubikey output");

        let plugin_recipient = PluginRecipient::from_str(&recipient_str)
            .expect("recipient string should parse as a plugin recipient");
        let plugin_name = plugin_recipient.plugin().to_owned();
        let plugin = RecipientPluginV1::new(
            &plugin_name,
            &[plugin_recipient],
            &[],
            NoCallbacks,
        )
        .expect("RecipientPluginV1::new (is age-plugin-{name} on PATH?)");

        let plaintext = b"tocken plugin spike";
        let mut ciphertext = Vec::new();
        let encryptor = Encryptor::with_recipients(std::iter::once(&plugin as &dyn age::Recipient))
            .expect("Encryptor::with_recipients");
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();

        let identity_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(identity_file.path(), &identity_text).unwrap();

        let mut child = Command::new("age")
            .arg("-d")
            .arg("-i")
            .arg(identity_file.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn age (is the age binary on PATH?)");
        child.stdin.as_mut().unwrap().write_all(&ciphertext).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "age -d failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, plaintext);
    }
}
