//! YubiKey detection + provisioning via age-plugin-yubikey subprocess.
//! Implementation lands in tasks #13, #14, #15 (plugin recipient
//! integration), #19 (spike).

#[cfg(test)]
mod tests {
    /// Spike (task #19): proves the `age::plugin::RecipientPluginV1`
    /// integration round-trips against a real YubiKey provisioned with
    /// `age-plugin-yubikey`. Encrypt-only — wizard never decrypts.
    ///
    /// Requires hardware: a YubiKey with an `age-plugin-yubikey` slot
    /// configured. Marked `#[ignore]` so CI skips it. Run locally with:
    ///
    ///     cd app/src-tauri && cargo test --lib -- --ignored
    ///
    /// or via `make test-hw`.
    #[test]
    #[ignore = "requires a YubiKey with age-plugin-yubikey provisioned"]
    fn plugin_recipient_round_trip() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        use std::str::FromStr;

        use age::plugin::{Recipient as PluginRecipient, RecipientPluginV1};
        use age::{Encryptor, NoCallbacks};

        // Pull the recipient + identity stub from age-plugin-yubikey.
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

        let recipient_str = identity_text
            .lines()
            .find_map(|line| {
                line.trim_start_matches('#')
                    .trim()
                    .strip_prefix("Recipient:")
                    .map(|v| v.trim().to_string())
            })
            .expect("no Recipient: line in age-plugin-yubikey output");

        // Build a plugin Recipient -> RecipientPluginV1 -> encrypt.
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

        // Decrypt via the age CLI + YubiKey identity stub. This path
        // matches what a recovery user would do by hand and is the
        // simplest end-to-end verification: if the bytes round-trip,
        // the plugin protocol is wired correctly.
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
