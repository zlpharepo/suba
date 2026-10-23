use serde_json::{json, Value};

use super::super::bindings::project;
use super::*;

fn reason<T>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::Document(reason)) => reason,
        _ => panic!("expected a static configuration error"),
    }
}

#[test]
fn collection_bindings_reject_wrong_shapes_owners_and_locations() {
    for malformed in [
        Value::Null,
        json!("private-name"),
        json!({}),
        json!(true),
        json!([7]),
        json!([{}]),
    ] {
        let document =
            json!({"outbounds": [{"type": "selector", "x-suba-collections": malformed}]});
        assert!(reason(project(&document)).starts_with("outbounds[0].x-suba-collections"));
    }
    for kind in [Value::Null, json!("direct"), json!("private-type")] {
        let document =
            json!({"outbounds": [{"type": kind, "x-suba-collections": ["private-name"]}]});
        assert_eq!(
            reason(project(&document)),
            "outbounds[0].x-suba-collections: is only allowed on selector or urltest outbounds"
        );
    }
    for document in [
        json!({"x-suba-collections": []}),
        json!({"outbounds": {"x-suba-collections": []}}),
        json!({"inbounds": [{"type": "selector", "x-suba-collections": []}]}),
        json!({"outbounds": [{"type": "selector", "nested": {"x-suba-collections": []}}]}),
        json!({"private-key": [{"x-suba-collections": ["private-name"]}]}),
    ] {
        assert_eq!(
            reason(project(&document)),
            "x-suba-collections: is only allowed on top-level selector or urltest outbounds"
        );
    }
    let (_scratch, store) = store();
    let unknown =
        json!({"outbounds": [{"type": "selector", "x-suba-collections": [], "unknown": true}]});
    assert!(
        reason(store.write_document(NAME, unknown, None, &OutboundSnapshot::default()))
            .contains("unknown")
    );
}

#[cfg(not(feature = "singbox"))]
#[test]
fn collection_bindings_require_rendering_even_with_manual_members() {
    let (_scratch, store) = store();
    let snapshot = OutboundSnapshot {
        selected: vec!["selected".to_owned()],
        ..Default::default()
    };
    let mut settings = store.settings().unwrap();
    settings.collections = snapshot.selected.clone();
    store.set_settings(&settings).unwrap();
    let authored = json!({"outbounds": [
        {"type": "direct", "tag": "manual"},
        {"type": "selector", "tag": "group", "outbounds": ["manual"], "x-suba-collections": ["selected"]}
    ]});
    let saved = store
        .write_document(NAME, authored.clone(), None, &snapshot)
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds[1].x-suba-collections: collection rendering is unavailable"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert_eq!(store.config_document(NAME).unwrap().value, authored);
    assert!(!store.assembled());
}

#[cfg(feature = "singbox")]
fn snapshot(tags: &[(&str, &[&str])]) -> OutboundSnapshot {
    OutboundSnapshot {
        selected: vec![
            "first".to_string(),
            "second".to_string(),
            "empty".to_string(),
        ],
        outbounds: tags
            .iter()
            .map(|(tag, collections)| GeneratedOutbound {
                value: json!({"type": "direct", "tag": tag}),
                collections: collections.iter().map(|name| (*name).to_owned()).collect(),
            })
            .collect(),
        unavailable: false,
        skipped: Vec::new(),
    }
}

#[cfg(feature = "singbox")]
fn select(store: &SingboxStore, snapshot: &OutboundSnapshot) {
    let mut settings = store.settings().unwrap();
    settings.collections = snapshot.selected.clone();
    store.set_settings(&settings).unwrap();
}

#[cfg(feature = "singbox")]
fn document(kind: &str, manual: &[&str], names: &[&str]) -> Value {
    json!({"outbounds": [
        {"type": "direct", "tag": "manual"},
        {"type": kind, "tag": "group", "outbounds": manual, "x-suba-collections": names}
    ]})
}

#[cfg(feature = "singbox")]
struct CoreGuard<'a>(&'a SingboxStore);

#[cfg(feature = "singbox")]
impl Drop for CoreGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.stop(Duration::from_secs(2));
    }
}

#[cfg(feature = "singbox")]
fn runtime(store: &SingboxStore) -> Value {
    serde_json::from_slice(&std::fs::read(store.dirs.config().join(CONFIG)).unwrap()).unwrap()
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_expand_manual_and_shared_generated_tags_once_in_order() {
    let snapshot = snapshot(&[("shared", &["first", "second"]), ("next", &["second"])]);
    for kind in ["selector", "urltest"] {
        let authored = document(
            kind,
            &["manual", "shared", "manual"],
            &["second", "first", "second"],
        );
        let before = authored.clone();
        let assembled = super::super::bindings::assemble(&authored, &snapshot).unwrap();
        let group = &assembled.config["outbounds"][1];
        assert_eq!(group["outbounds"], json!(["manual", "shared", "next"]));
        assert!(group.get("x-suba-collections").is_none());
        assert_eq!(assembled.config["outbounds"][0], authored["outbounds"][0]);
        assert_eq!(
            assembled.config["outbounds"][2],
            snapshot.outbounds[0].value
        );
        assert_eq!(
            assembled.config["outbounds"][3],
            snapshot.outbounds[1].value
        );
        assert_eq!(authored, before);
    }
    let ordinary = json!({"outbounds": [{"type": "selector", "tag": "group", "outbounds": ["shared", "shared"]}]});
    let values: Vec<_> = snapshot
        .outbounds
        .iter()
        .map(|entry| entry.value.clone())
        .collect();
    assert_eq!(project(&ordinary).unwrap(), ordinary);
    assert_eq!(
        super::super::bindings::assemble(&ordinary, &snapshot).unwrap(),
        suba_singbox::assemble::assemble(&ordinary, &values).unwrap()
    );
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_persist_only_authored_values_across_all_writes() {
    let (_scratch, store) = store();
    let snapshot = snapshot(&[("derived", &["first", "second"])]);
    select(&store, &snapshot);
    let authored = document("selector", &["manual"], &["first", "second"]);
    let (schema, _) = store.parsed_schema().unwrap();
    assert!(
        matches!(schema.validate(&authored), Verdict::Failed(_)),
        "native schemas know nothing about the extension"
    );
    assert!(!matches!(
        schema.validate(&project(&authored).unwrap()),
        Verdict::Failed(_)
    ));
    let saved = store
        .write_document(NAME, authored.clone(), None, &snapshot)
        .unwrap();
    assert!(saved.warnings.is_empty());
    assert_eq!(store.config_document(NAME).unwrap().value, authored);
    assert_eq!(store.config_document(NAME).unwrap().etag, saved.etag);
    let catalog =
        serde_json::to_value(store.references(NAME, &snapshot.outbounds).unwrap()).unwrap();
    assert_eq!(
        catalog.as_array().unwrap().last().unwrap()["value"],
        authored["outbounds"][1]
    );
    store.create_config("copy", Some(NAME)).unwrap();
    assert_eq!(store.config_document("copy").unwrap().value, authored);
    store.remove_config("copy").unwrap();

    let changed = document("urltest", &["manual"], &["second"]);
    let saved_section = store
        .write_section(
            NAME,
            "outbounds",
            changed["outbounds"].clone(),
            Some(&saved.etag),
            &snapshot,
        )
        .unwrap();
    assert!(saved_section.warnings.is_empty());
    assert_eq!(store.config_document(NAME).unwrap().value, changed);
    assert_ne!(saved.etag, saved_section.etag);
    assert!(matches!(
        store.write_document(NAME, authored.clone(), Some(&saved.etag), &snapshot),
        Err(Error::Stale)
    ));
    let saved_entry = store
        .write_entry(
            NAME,
            "outbounds",
            "group",
            authored["outbounds"][1].clone(),
            Some(&saved_section.etag),
            &snapshot,
        )
        .unwrap();
    assert!(saved_entry.warnings.is_empty());
    assert_eq!(store.config_document(NAME).unwrap().value, authored);
    assert_eq!(
        store.entry(NAME, "outbounds", "group").unwrap().0,
        authored["outbounds"][1]
    );
    store
        .remove_entry(
            NAME,
            "outbounds",
            "manual",
            Some(&saved_entry.etag),
            &snapshot,
        )
        .unwrap();
    assert_eq!(
        store.entry(NAME, "outbounds", "group").unwrap().0,
        authored["outbounds"][1]
    );
    store
        .remove_section(NAME, "outbounds", None, &snapshot)
        .unwrap();
    assert_eq!(store.config_document(NAME).unwrap().value, json!({}));
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_save_unavailable_drafts_but_refuse_start_without_fallback() {
    let (_scratch, store) = store();
    let mut snapshot = snapshot(&[]);
    select(&store, &snapshot);
    let empty = document("selector", &[], &["empty"]);
    let saved = store
        .write_document(NAME, empty.clone(), None, &snapshot)
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds[1].outbounds: must contain at least one member after collection expansion"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert!(!store.assembled());

    let manual = document("selector", &["manual"], &["empty"]);
    assert!(store
        .write_document(NAME, manual.clone(), None, &snapshot)
        .unwrap()
        .warnings
        .is_empty());
    assert_eq!(
        store.assemble(&snapshot).unwrap().config["outbounds"][1]["outbounds"],
        json!(["manual"])
    );

    let unselected = document("selector", &["manual"], &["private-name"]);
    let saved = store
        .write_section(
            NAME,
            "outbounds",
            unselected["outbounds"].clone(),
            None,
            &snapshot,
        )
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds[1].x-suba-collections[0]: the bound collection is not selected"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert!(!store.assembled());

    snapshot.unavailable = true;
    let saved = store
        .write_entry(
            NAME,
            "outbounds",
            "group",
            manual["outbounds"][1].clone(),
            None,
            &snapshot,
        )
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds.x-suba-collections: a selected collection is unavailable"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert_eq!(store.config_document(NAME).unwrap().value, manual);
    assert!(!store.assembled());
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_do_not_repair_stale_manual_members_or_defaults() {
    let (_scratch, store) = store();
    let snapshot = snapshot(&[("derived", &["first"])]);
    select(&store, &snapshot);
    let mut authored = document("selector", &["manual", "private-stale-tag"], &["first"]);
    let saved = store
        .write_document(NAME, authored.clone(), None, &snapshot)
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds[1].outbounds[1]: a referenced tag is not declared"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert_eq!(store.config_document(NAME).unwrap().value, authored);

    authored["outbounds"][1]["outbounds"] = json!([]);
    authored["outbounds"][1]["default"] = json!("manual");
    let saved = store
        .write_document(NAME, authored.clone(), None, &snapshot)
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["outbounds[1].default: must name a member of this selector"]
    );
    assert_eq!(reason(store.start(&snapshot)), saved.warnings[0]);
    assert_eq!(store.config_document(NAME).unwrap().value, authored);
    authored["outbounds"][1]["default"] = json!("derived");
    assert!(store
        .write_document(NAME, authored, None, &snapshot)
        .unwrap()
        .warnings
        .is_empty());
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_restart_preflight_leaves_running_core_and_product_untouched() {
    let (_scratch, store) = store();
    let _core = CoreGuard(&store);
    let mut snapshot = snapshot(&[("derived", &["first"])]);
    select(&store, &snapshot);
    let valid = document("selector", &["manual"], &["first"]);
    store
        .write_document(NAME, valid.clone(), None, &snapshot)
        .unwrap();
    let pid = store.start(&snapshot).unwrap();
    wait_for(&store, "started");
    let product = runtime(&store);
    let mut invalid_native = valid.clone();
    invalid_native["log"] = json!({"level": 7});
    for authored in [
        document("selector", &[], &["empty"]),
        document("urltest", &["manual"], &["private-unselected"]),
        document("selector", &["private-stale"], &["first"]),
        invalid_native,
    ] {
        std::fs::write(
            store.document_dir.join(document_file(NAME)),
            serde_json::to_vec(&authored).unwrap(),
        )
        .unwrap();
        assert!(!reason(store.restart(&snapshot, Duration::from_secs(2))).contains("private-"));
        assert_eq!(store.status().pid, Some(pid));
        assert!(store.status().running);
        assert!(store.status().exits.is_empty());
        assert_eq!(runtime(&store), product);
    }
    store.write_document(NAME, valid, None, &snapshot).unwrap();
    snapshot.unavailable = true;
    assert_eq!(
        reason(store.restart(&snapshot, Duration::from_secs(2))),
        "outbounds.x-suba-collections: a selected collection is unavailable"
    );
    snapshot.unavailable = false;
    let mut settings = store.settings().unwrap();
    settings.collections.clear();
    store.set_settings(&settings).unwrap();
    assert_eq!(
        store.status().pid,
        Some(pid),
        "selection does not auto-restart"
    );
    assert_eq!(
        reason(store.restart(&snapshot, Duration::from_secs(2))),
        "outbounds.x-suba-collections: collection selection changed; retry the operation"
    );
    snapshot.selected.clear();
    assert_eq!(
        reason(store.restart(&snapshot, Duration::from_secs(2))),
        "outbounds[1].x-suba-collections[0]: the bound collection is not selected"
    );
    assert_eq!(store.status().pid, Some(pid));
    assert!(store.status().exits.is_empty());
    assert_eq!(runtime(&store), product);
    store.stop(Duration::from_secs(2)).unwrap();
}

#[cfg(feature = "singbox")]
#[test]
fn collection_bindings_restart_expands_the_next_snapshot_without_persisting_tags() {
    let (_scratch, store) = store();
    let _core = CoreGuard(&store);
    let old = snapshot(&[("old", &["first"])]);
    let new = snapshot(&[("new", &["first", "second"])]);
    select(&store, &old);
    let authored = document("urltest", &["manual"], &["first", "second"]);
    store
        .write_document(NAME, authored.clone(), None, &old)
        .unwrap();
    store.start(&old).unwrap();
    wait_for(&store, "started");
    assert_eq!(
        runtime(&store)["outbounds"][1]["outbounds"],
        json!(["manual", "old"])
    );
    assert_eq!(
        store.assemble(&new).unwrap().config["outbounds"][1]["outbounds"],
        json!(["manual", "new"])
    );
    assert_eq!(
        runtime(&store)["outbounds"][1]["outbounds"],
        json!(["manual", "old"]),
        "preview does not reload the core"
    );
    store.restart(&new, Duration::from_secs(2)).unwrap();
    assert_eq!(
        runtime(&store)["outbounds"][1]["outbounds"],
        json!(["manual", "new"])
    );
    assert!(runtime(&store)["outbounds"][1]
        .get("x-suba-collections")
        .is_none());
    assert_eq!(runtime(&store)["outbounds"][2]["tag"], "new");
    assert_eq!(store.config_document(NAME).unwrap().value, authored);
    store.stop(Duration::from_secs(2)).unwrap();
}
