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
    assert_eq!(token.len(), 46);
    assert_ne!(token, issue("alice".into(), "test".into()).1);
    assert!(valid_token(&token));
    assert!(authenticate(&app, &token).is_some());
    for i in 0..token.len() {
        let mut altered = token.as_bytes().to_vec();
        altered[i] = if altered[i] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(altered).unwrap();
        assert!(authenticate(&app, &changed).is_none());
        for invalid in [b'_', b'G', b'A', b' ', b'\n', 0xff] {
            let mut altered = token.as_bytes().to_vec();
            altered[i] = invalid;
            if let Ok(changed) = String::from_utf8(altered) {
                let _ = valid_token(&changed);
            }
        }
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
    for invalid in [
        format!("kg-{}B", "A".repeat(42)), // nonzero trailing padding bits
        format!("{token}="),
        format!("kg-{}", "+".repeat(43)),
        format!("kg-{}", "/".repeat(43)),
        format!("kg-{}", " ".repeat(43)),
        format!("kg-{}", "é".repeat(21)),
    ] {
        assert!(!valid_token(&invalid));
    }
    assert!(valid_token(&format!("kg-{}8", "_".repeat(42))));
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
