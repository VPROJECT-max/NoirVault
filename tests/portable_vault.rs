use noirvault::crypto::{
    decrypt_data, decrypt_v2, decrypt_v2_with_key, derive_key, derive_v2_key_for_envelope,
    encrypt_data, encrypt_v2, is_v2_envelope, reencrypt_v2_with_key, VaultError, V2_PREFIX,
};

#[test]
fn standalone_authenticator_and_metadata_survive_portable_roundtrip() {
    let payload = br#"{"items":[{"id":"otp-1","title":"GitHub","description":"alice","totp_secret":"JBSWY3DPEHPK3PXP","tags":["work"],"item_type":"authenticator","content":"","website":"github.com","notes":"recovery elsewhere","favorite":true}],"trusted_machines":[]}"#;
    let vault = noirvault::vault::VaultData::from_bytes(payload).unwrap();
    let serialized = vault.to_bytes();
    let restored = noirvault::vault::VaultData::from_bytes(&serialized).unwrap();
    let item = &restored.items[0];
    assert_eq!(item.item_type, "authenticator");
    assert!(item.content.is_empty());
    assert_eq!(item.website, "github.com");
    assert_eq!(item.notes, "recovery elsewhere");
    assert!(item.favorite);
    assert_eq!(item.totp_secret, "JBSWY3DPEHPK3PXP");
}

#[test]
fn legacy_items_default_new_metadata_without_losing_secrets() {
    let payload = br#"{"items":[{"id":"1","title":"Old","item_type":"password","content":"secret"}]}"#;
    let vault = noirvault::vault::VaultData::from_bytes(payload).unwrap();
    assert_eq!(vault.items[0].content, "secret");
    assert!(!vault.items[0].favorite);
    assert!(vault.items[0].website.is_empty());
}

#[test]
fn v2_round_trip_uses_only_the_master_password() {
    let payload = br#"{"items":[],"trusted_machines":[]}"#;

    let envelope = encrypt_v2("correct horse battery staple", payload);

    assert!(envelope.starts_with(V2_PREFIX));
    assert!(is_v2_envelope(&envelope));
    assert_eq!(
        decrypt_v2("correct horse battery staple", &envelope)
            .expect("the matching password decrypts the envelope")
            .as_slice(),
        payload
    );
}

#[test]
fn v2_rejects_an_incorrect_master_password() {
    let envelope = encrypt_v2("right password", b"private data");

    assert!(matches!(
        decrypt_v2("wrong password", &envelope),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn v2_rejects_malformed_or_unsupported_envelopes() {
    assert!(matches!(
        decrypt_v2("password", b"NVLT\x02"),
        Err(VaultError::MalformedEnvelope)
    ));
    assert!(!is_v2_envelope(b"NVLT\x01not-a-v2-vault"));
}

#[test]
fn derived_key_unlocks_and_reencrypts_without_rotating_salt() {
    let first_payload = br#"{"items":[],"trusted_machines":[]}"#;
    let second_payload = br#"{"items":[{"id":"1"}],"trusted_machines":[]}"#;
    let first = encrypt_v2("master password", first_payload);
    let key = derive_v2_key_for_envelope("master password", &first)
        .expect("a valid v2 envelope derives its current key");

    let second = reencrypt_v2_with_key(key.as_slice(), &first, second_payload)
        .expect("the current key re-encrypts the vault");

    assert_eq!(&first[5..21], &second[5..21], "the Argon2 salt must remain stable");
    assert_ne!(&first[21..45], &second[21..45], "every save must rotate the nonce");
    assert_eq!(
        decrypt_v2_with_key(key.as_slice(), &second)
            .expect("the same derived key decrypts the updated envelope")
            .as_slice(),
        second_payload
    );
}

#[test]
fn key_unlock_rejects_wrong_length_and_wrong_key() {
    let envelope = encrypt_v2("master password", b"private data");
    let correct_key = derive_v2_key_for_envelope("master password", &envelope)
        .expect("the password derives a key");
    let wrong_key = [0xA5_u8; 32];

    assert!(matches!(
        decrypt_v2_with_key(&correct_key.as_slice()[..31], &envelope),
        Err(VaultError::InvalidKey)
    ));
    assert!(matches!(
        decrypt_v2_with_key(&wrong_key, &envelope),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn legacy_envelope_stays_readable_for_a_one_time_desktop_migration() {
    let salt = [7_u8; 16];
    let key = derive_key("legacy password", b"legacy keyfile", &salt);
    let encrypted = encrypt_data(b"legacy plaintext", &key);
    let mut legacy_envelope = salt.to_vec();
    legacy_envelope.extend_from_slice(&encrypted);

    assert!(!is_v2_envelope(&legacy_envelope));
    let legacy_key = derive_key("legacy password", b"legacy keyfile", &legacy_envelope[..16]);
    assert_eq!(
        decrypt_data(&legacy_envelope[16..], &legacy_key)
            .expect("legacy vault decrypts with its one-time keyfile")
            .as_slice(),
        b"legacy plaintext"
    );
}
