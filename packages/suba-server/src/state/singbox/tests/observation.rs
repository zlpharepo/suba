use super::*;

#[test]
fn observation_follows_the_launched_config_not_subsequent_edits_or_selection() {
    let (_scratch, store) = store();
    assert!(store.observation_run().is_none());
    store.start(&Contributions::default()).unwrap();
    let first = store.observation_run().unwrap();
    assert_eq!(first.config, NAME);
    store.create_config("other", None).unwrap();
    let mut settings = store.settings().unwrap();
    settings.config = Some("other".to_string());
    store.set_settings(&settings).unwrap();
    store
        .write_product(&serde_json::json!({"services": []}))
        .unwrap();
    assert_eq!(store.observation_run().unwrap().id, first.id);
    assert_eq!(store.observation_run().unwrap().config, NAME);
    store
        .restart(&Contributions::default(), Duration::from_secs(2))
        .unwrap();
    let second = store.observation_run().unwrap();
    assert_ne!(second.id, first.id);
    assert_eq!(second.config, "other");
    store.stop(Duration::from_secs(2)).unwrap();
    assert!(store.observation_run().is_none());
}
