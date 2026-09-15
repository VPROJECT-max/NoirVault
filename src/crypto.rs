use sha2::{Sha256, Digest};
use crate::memory::SecureBuffer;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce
};
use rand::{rngs::OsRng, RngCore};

pub const V2_PREFIX: &[u8; 5] = b"NVLT\x02";
const V2_SALT_LEN: usize = 16;
const V2_NONCE_LEN: usize = 24;
const V2_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    MalformedEnvelope,
    AuthenticationFailed,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEnvelope => formatter.write_str("The vault file is malformed or uses an unsupported format."),
            Self::AuthenticationFailed => formatter.write_str("The master password is incorrect or the vault data was modified."),
        }
    }
}

impl std::error::Error for VaultError {}

pub fn derive_key(password: &str, keyfile_bytes: &[u8], salt: &[u8]) -> SecureBuffer {
    let params = Params::new(
        65536, // m_cost (64 MB)
        3,     // t_cost
        1,     // p_cost
        Some(32), // output_len
    ).unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Hash the keyfile to get a fixed size digest
    let mut hasher = Sha256::new();
    hasher.update(keyfile_bytes);
    let keyfile_hash = hasher.finalize();

    // Combine password and keyfile hash
    let mut combined = SecureBuffer::new(password.len() + keyfile_hash.len());
    combined.as_mut_slice()[..password.len()].copy_from_slice(password.as_bytes());
    combined.as_mut_slice()[password.len()..].copy_from_slice(&keyfile_hash);

    let mut key = SecureBuffer::new(32);
    argon2.hash_password_into(combined.as_slice(), salt, key.as_mut_slice())
        .expect("Failed to derive key");

    key
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn argon2id() -> Argon2<'static> {
    let params = Params::new(65536, 3, 1, Some(32)).expect("The fixed Argon2id parameters are valid");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn derive_v2_key(password: &str, salt: &[u8; V2_SALT_LEN]) -> SecureBuffer {
    let mut key = SecureBuffer::new(32);
    argon2id()
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .expect("The fixed Argon2id output length is valid");
    key
}

pub fn is_v2_envelope(data: &[u8]) -> bool {
    data.starts_with(V2_PREFIX)
}

pub fn encrypt_v2(password: &str, data: &[u8]) -> Vec<u8> {
    let salt = generate_salt();
    let key = derive_v2_key(password, &salt);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));

    let mut nonce_bytes = [0u8; V2_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), data)
        .expect("XChaCha20Poly1305 encryption with a fixed-size nonce succeeds");

    let mut envelope = Vec::with_capacity(V2_PREFIX.len() + salt.len() + nonce_bytes.len() + ciphertext.len());
    envelope.extend_from_slice(V2_PREFIX);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    envelope
}

pub fn decrypt_v2(password: &str, envelope: &[u8]) -> Result<SecureBuffer, VaultError> {
    let minimum_length = V2_PREFIX.len() + V2_SALT_LEN + V2_NONCE_LEN + V2_TAG_LEN;
    if !is_v2_envelope(envelope) || envelope.len() < minimum_length {
        return Err(VaultError::MalformedEnvelope);
    }

    let salt_start = V2_PREFIX.len();
    let nonce_start = salt_start + V2_SALT_LEN;
    let ciphertext_start = nonce_start + V2_NONCE_LEN;
    let mut salt = [0u8; V2_SALT_LEN];
    salt.copy_from_slice(&envelope[salt_start..nonce_start]);
    let key = derive_v2_key(password, &salt);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));

    cipher
        .decrypt(XNonce::from_slice(&envelope[nonce_start..ciphertext_start]), &envelope[ciphertext_start..])
        .map(|plaintext| SecureBuffer::from_slice(&plaintext))
        .map_err(|_| VaultError::AuthenticationFailed)
}

pub fn encrypt_data(data: &[u8], key: &SecureBuffer) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let mut ciphertext = cipher.encrypt(nonce, data).expect("encryption failure!");
    
    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.append(&mut ciphertext);
    
    result
}

pub fn decrypt_data(data: &[u8], key: &SecureBuffer) -> Option<SecureBuffer> {
    if data.len() < 24 {
        return None;
    }
    let (nonce_bytes, ciphertext) = data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => Some(SecureBuffer::from_slice(&plaintext)),
        Err(_) => None,
    }
}
