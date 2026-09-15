use sha2::{Sha256, Digest};
use crate::memory::SecureBuffer;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, Key, XNonce
};
use rand::{rngs::OsRng, RngCore};

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
