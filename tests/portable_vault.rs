use noirvault::crypto::{decrypt_v2, encrypt_v2, is_v2_envelope, VaultError, V2_PREFIX};

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
