//! Hardware spike (task #23) for #3.
//!
//! Verifies that `age::plugin::IdentityPluginV1` decrypts via
//! `age-plugin-yubikey` while invoking our `Callbacks::display_message`
//! at least once. The structural unknown is NOT the decrypt call itself
//! (mechanical) but that the callback path fires from inside the plugin
//! during decrypt without deadlocking the host. If `display_message`
//! never fires, the wizard pattern of "touch the key when blinking"
//! has no surface for us to render — we'd need a different mechanism.
//!
//! Run with: `make test-hw`.

use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use age::plugin::{Identity as PluginIdentity, IdentityPluginV1, Recipient as PluginRecipient, RecipientPluginV1};
use age::secrecy::SecretString;
use age::{Callbacks, Decryptor, Encryptor};

#[derive(Clone)]
struct ProbeCallbacks {
    display_count: Arc<AtomicUsize>,
    fired: Arc<AtomicBool>,
}

impl ProbeCallbacks {
    fn new() -> Self {
        Self {
            display_count: Arc::new(AtomicUsize::new(0)),
            fired: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Callbacks for ProbeCallbacks {
    fn display_message(&self, message: &str) {
        eprintln!("[spike] plugin display_message: {message}");
        self.fired.store(true, Ordering::Release);
        self.display_count.fetch_add(1, Ordering::AcqRel);
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        None
    }
}

/// Decrypt round-trip via plugin recipient + plugin identity, asserting
/// that `display_message` fires at least once during the decrypt path.
#[test]
#[ignore = "requires a YubiKey with age-plugin-yubikey provisioned"]
fn identity_plugin_decrypt_round_trip_with_callbacks() {
    let identity_text = run_capture("age-plugin-yubikey", &["--identity"]);
    let recipient_str = parse_recipient(&identity_text).expect("Recipient: line");
    let identity_str = parse_identity_stub(&identity_text).expect("AGE-PLUGIN-YUBIKEY identity stub");

    // Encrypt to the YubiKey recipient via plugin protocol.
    let plugin_recipient = PluginRecipient::from_str(&recipient_str).expect("parse plugin recipient");
    let recipient_plugin_name = plugin_recipient.plugin().to_owned();
    let recipient_plugin = RecipientPluginV1::new(
        &recipient_plugin_name,
        &[plugin_recipient],
        &[],
        age::NoCallbacks,
    )
    .expect("RecipientPluginV1::new");

    let plaintext = b"tocken decrypt-callbacks spike";
    let mut ciphertext = Vec::new();
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient_plugin as &dyn age::Recipient))
        .expect("Encryptor::with_recipients");
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt via IdentityPluginV1 with our probe callbacks.
    let plugin_identity = PluginIdentity::from_str(&identity_str).expect("parse plugin identity stub");
    let identity_plugin_name = plugin_identity.plugin().to_owned();
    let probe = ProbeCallbacks::new();
    let identity_plugin = IdentityPluginV1::new(
        &identity_plugin_name,
        &[plugin_identity],
        probe.clone(),
    )
    .expect("IdentityPluginV1::new");

    let decryptor = Decryptor::new_buffered(ciphertext.as_slice()).expect("Decryptor::new_buffered");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity_plugin as &dyn age::Identity))
        .expect("decrypt");
    let mut recovered = Vec::new();
    use std::io::Read;
    reader.read_to_end(&mut recovered).expect("read decrypted plaintext");

    assert_eq!(recovered, plaintext, "plaintext mismatch");
    assert!(
        probe.fired.load(Ordering::Acquire),
        "Callbacks::display_message never fired during decrypt — \
         the touch-prompt UX surface for #3 needs a different mechanism"
    );
    eprintln!(
        "[spike] display_message fired {} time(s); callback path is wired",
        probe.display_count.load(Ordering::Acquire)
    );
}

fn run_capture(cmd: &str, args: &[&str]) -> String {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{cmd}: {e} — is it on PATH?"));
    assert!(
        output.status.success(),
        "{cmd} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn parse_recipient(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim_start_matches('#')
            .trim()
            .strip_prefix("Recipient:")
            .map(|v| v.trim().to_string())
    })
}

fn parse_identity_stub(text: &str) -> Option<String> {
    text.lines()
        .find(|line| line.starts_with("AGE-PLUGIN-YUBIKEY-"))
        .map(|s| s.trim().to_string())
}
