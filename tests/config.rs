use keygate::config::Config;
use serde_json::json;
use uuid::Uuid;

#[test]
fn catalog_preserves_admin_order_and_normalizes_names() {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let config = Config::parse(
        &json!({"applications": [
            {"id": first, "name": "  First API  ", "group": "first"},
            {"id": second, "name": "第二个 API", "group": "second"}
        ]})
        .to_string(),
    )
    .unwrap();
    assert_eq!(config.applications().len(), 2);
    assert_eq!(config.applications()[0].id, first);
    assert_eq!(config.applications()[1].id, second);
    assert_eq!(config.application(first).unwrap().name, "First API");
    assert_eq!(config.application(second).unwrap().name, "第二个 API");
    assert!(config.contains(first));
    assert!(config.contains(second));
    assert!(!config.contains(Uuid::nil()));
    assert!(config.application(Uuid::nil()).is_none());
    let empty = Config::parse(r#"{"applications":[]}"#).unwrap();
    assert!(empty.applications().is_empty());
    assert!(!empty.contains(first));
}

#[test]
fn catalog_rejects_ambiguous_or_misspelled_configuration() {
    let id = Uuid::new_v4();
    for invalid in [
        String::new(),
        "{}".into(),
        r#"{"applications":[],"applications":[]}"#.into(),
        r#"{"applications":[],"rules":[]}"#.into(),
        format!(r#"{{"applications":[{{"id":"{id}","name":"A","name":"B"}}]}}"#),
        json!({"applications": [{"id": id, "name": "A", "keys": []}]}).to_string(),
        json!({"applications": [{"id": id, "name": "A"}, {"id": id, "name": "B"}]}).to_string(),
        json!({"applications": [{"id": Uuid::nil(), "name": "A"}]}).to_string(),
    ] {
        assert!(Config::parse(&invalid).is_err(), "accepted {invalid}");
    }
    for name in [
        "".into(),
        "  ".into(),
        "x".repeat(129),
        "x\ny".into(),
        "é".repeat(65),
    ] {
        assert!(
            Config::parse(
                &json!({"applications": [{"id": id, "name": name, "group": "test-group"}]})
                    .to_string()
            )
            .is_err()
        );
    }
    assert!(
        Config::parse(
            &json!({"applications": [{"id": id, "name": "é".repeat(64), "group": "test-group"}]})
                .to_string()
        )
        .is_ok()
    );
}

#[test]
fn catalog_requires_an_explicit_application_group() {
    let id = Uuid::new_v4();
    for group in [
        "".to_string(),
        " ".to_string(),
        "a\nb".to_string(),
        "a".repeat(129),
    ] {
        assert!(
            Config::parse(
                &json!({"applications":[{"id":id,"name":"A","group":group}]}).to_string()
            )
            .is_err()
        );
    }
    assert!(Config::parse(&json!({"applications":[{"id":id,"name":"A"}]}).to_string()).is_err());
}
