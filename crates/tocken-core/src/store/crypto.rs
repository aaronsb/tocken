use std::io::{Read, Write};

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor, Identity, Recipient};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("age encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("age decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no recipients provided")]
    NoRecipients,
}

/// Encrypt with a single passphrase recipient (scrypt mode).
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: SecretString,
) -> Result<Vec<u8>, CryptoError> {
    let encryptor = Encryptor::with_user_passphrase(passphrase);
    encrypt(encryptor, plaintext)
}

/// Decrypt a passphrase-encrypted (scrypt) age file.
pub fn decrypt_with_passphrase(
    ciphertext: &[u8],
    passphrase: SecretString,
) -> Result<Vec<u8>, CryptoError> {
    let identity = age::scrypt::Identity::new(passphrase);
    let decryptor = Decryptor::new_buffered(ciphertext)?;
    decrypt(decryptor, std::iter::once(&identity as &dyn Identity))
}

/// Encrypt with one or more public-key recipients.
pub fn encrypt_to_recipients(
    plaintext: &[u8],
    recipients: &[&dyn Recipient],
) -> Result<Vec<u8>, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    let encryptor = Encryptor::with_recipients(recipients.iter().copied())?;
    encrypt(encryptor, plaintext)
}

/// Decrypt using one identity (caller picks which one to try).
pub fn decrypt_with_identity(
    ciphertext: &[u8],
    identity: &dyn Identity,
) -> Result<Vec<u8>, CryptoError> {
    let decryptor = Decryptor::new_buffered(ciphertext)?;
    decrypt(decryptor, std::iter::once(identity))
}

fn encrypt(encryptor: Encryptor, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

fn decrypt<'a>(
    decryptor: Decryptor<&[u8]>,
    identities: impl Iterator<Item = &'a dyn Identity>,
) -> Result<Vec<u8>, CryptoError> {
    let mut reader = decryptor.decrypt(identities)?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_round_trip() {
        // Use a low scrypt work factor for tests so they don't hang.
        let passphrase = SecretString::from("correct horse battery staple");
        let plaintext = b"secret seed material";

        // encrypt with low work factor by going through scrypt::Recipient directly
        let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
        recipient.set_work_factor(2);
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
        let ciphertext = encrypt(encryptor, plaintext).unwrap();

        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(2);
        let decryptor = Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        let recovered = decrypt(decryptor, std::iter::once(&identity as &dyn Identity)).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn multi_recipient_each_decrypts_independently() {
        let alice = age::x25519::Identity::generate();
        let bob = age::x25519::Identity::generate();
        let alice_pub = alice.to_public();
        let bob_pub = bob.to_public();

        let plaintext = b"shared seed material";
        let ciphertext = encrypt_to_recipients(
            plaintext,
            &[&alice_pub as &dyn Recipient, &bob_pub as &dyn Recipient],
        )
        .unwrap();

        let from_alice = decrypt_with_identity(&ciphertext, &alice as &dyn Identity).unwrap();
        let from_bob = decrypt_with_identity(&ciphertext, &bob as &dyn Identity).unwrap();
        assert_eq!(from_alice, plaintext);
        assert_eq!(from_bob, plaintext);
    }

    #[test]
    fn x25519_wrong_identity_fails() {
        let alice = age::x25519::Identity::generate();
        let stranger = age::x25519::Identity::generate();
        let ciphertext =
            encrypt_to_recipients(b"x", &[&alice.to_public() as &dyn Recipient]).unwrap();
        let result = decrypt_with_identity(&ciphertext, &stranger as &dyn Identity);
        assert!(result.is_err());
    }

    #[test]
    fn empty_recipient_list_rejected() {
        let result = encrypt_to_recipients(b"x", &[]);
        assert!(matches!(result, Err(CryptoError::NoRecipients)));
    }

    #[test]
    fn passphrase_wrong_phrase_fails() {
        let passphrase = SecretString::from("right");
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(2);
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
        let ciphertext = encrypt(encryptor, b"x").unwrap();

        let wrong = SecretString::from("wrong");
        let mut identity = age::scrypt::Identity::new(wrong);
        identity.set_max_work_factor(2);
        let decryptor = Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        let result = decrypt(decryptor, std::iter::once(&identity as &dyn Identity));
        assert!(result.is_err());
    }
}
