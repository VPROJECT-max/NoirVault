use noirvault::crypto::{
    decrypt_data, decrypt_v2, derive_key, encrypt_data, encrypt_v2, is_v2_envelope, VaultError,
    V2_PREFIX,
};

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
