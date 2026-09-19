use keygate::model::*;
use uuid::Uuid;
#[test]
fn token_mutations_never_authenticate() {
    let app_id = Uuid::new_v4();
    let (key, token) = issue("alice".into(), "test".into());
    let app = Application {
        id: app_id,
        name: "test".into(),
        keys: vec![key.clone()],
    };
    assert!(token.starts_with("kg-"));
    assert_eq!(token.len(), 49);
    assert_eq!(token.bytes().filter(|b| *b == b'-').count(), 1);
    assert!(token[3..].bytes().all(|b| b.is_ascii_alphabetic()));
    assert_ne!(token, issue("alice".into(), "test".into()).1);
    assert!(valid_token(&token));
    assert!(authenticate(&app, &token).is_some());
    for i in 0..token.len() {
        let mut altered = token.as_bytes().to_vec();
        altered[i] = if altered[i] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(altered).unwrap();
        assert!(authenticate(&app, &changed).is_none());
    }
    for input in [
        "".to_owned(),
        "é".repeat(67),
        "_".repeat(134),
        "kgt_".to_owned() + &"x".repeat(130),
        token.to_uppercase(),
    ] {
        assert!(!valid_token(&input));
    }
    let mut ownerless = app.clone();
    ownerless.keys[0].owner.clear();
    assert!(authenticate(&ownerless, &token).is_none());
    let mut revoked = app;
    revoked.keys[0].revoked = true;
    assert!(authenticate(&revoked, &token).is_none());
    assert!(constant_eq("same", "same"));
    assert!(!constant_eq("same", "different"));
    assert_eq!(
        digest("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn alphabetic_keys_accept_both_cases_and_reject_nonletters_and_wrong_lengths() {
    for suffix in ["A".repeat(46), "z".repeat(46), "aZ".repeat(23)] {
        assert!(valid_token(&format!("kg-{suffix}")));
    }
    for position in 0..46 {
        for invalid in [
            '0', '9', '-', '_', '+', '/', '=', ' ', '\t', '\n', 'é', '京', 'K',
        ] {
            let token = format!(
                "kg-{}{}{}",
                "A".repeat(position),
                invalid,
                "z".repeat(45 - position)
            );
            assert!(
                !valid_token(&token),
                "accepted nonletter at position {position}: {invalid:?}"
            );
        }
    }
    for invalid in ['é', '京', 'K'] {
        let token = format!("kg-{invalid}{}", "A".repeat(46 - invalid.len_utf8()));
        assert_eq!(token.len(), 49);
        assert!(!valid_token(&token));
    }
    // A 43-character suffix is reserved for already-issued canonical base64url keys.
    for length in [0, 1, 32, 42, 44, 45, 47, 48, 64, 128] {
        assert!(!valid_token(&format!("kg-{}", "A".repeat(length))));
    }
    for prefix in ["", "KG-", "Kg-", "kg_", "kg", "kg--", "kgt-"] {
        assert!(!valid_token(&format!("{prefix}{}", "A".repeat(46))));
    }
}

#[test]
fn legacy_keys_keep_strict_canonical_base64url_validation() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    for bytes in [[0; 32], [0xfb; 32], [0xff; 32]] {
        let token = format!("kg-{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(token.len(), 46);
        assert!(valid_token(&token));
    }
    assert!(valid_token(&format!("kg-{}8", "_".repeat(42))));
    for invalid in [
        format!("kg-{}B", "A".repeat(42)), // nonzero trailing padding bits
        format!("kg-{}=", "A".repeat(43)),
        format!("kg-{}", "+".repeat(43)),
        format!("kg-{}", "/".repeat(43)),
        format!("kg-{}", " ".repeat(43)),
        format!("kg-{}", "é".repeat(21)),
    ] {
        assert!(!valid_token(&invalid));
    }
}
