use serde_json::{json, Value};

use super::{body, Server};
use crate::config::{config_path, read_config};

const MODULE: &str = "/api/cores/sing-box";
const SETTINGS_BASENAME: &str = "sing-box";

/// The module document as an operator would find it on disk.
///
/// Read the way the server writes it, so this holds for either configuration
/// format rather than only the one this build happens to compile.
fn settings_file(server: &Server) -> Value {
    let path = config_path(server.root.join("config"), SETTINGS_BASENAME);
    let settings: crate::state::singbox::Settings =
        read_config(path.parent().unwrap().to_str().unwrap(), SETTINGS_BASENAME).unwrap();

    serde_json::to_value(settings).unwrap()
}

#[tokio::test]
async fn the_flag_is_kept_when_a_save_does_not_speak_about_it() {
    let server = Server::start().await;

    // Turning it on.
    let on = body(
        server
            .put_json(
                MODULE,
                json!({"config": "default", "privilege": "operator", "autostart": true}),
            )
            .await,
    )
    .await;
    assert_eq!(on["autostart"], true);
    assert_eq!(settings_file(&server)["autostart"], true, "on disk");

    // A save whose business is something else entirely: no `autostart` key.
    let later = body(
        server
            .put_json(
                MODULE,
                json!({"config": "default", "privilege": "root", "collections": []}),
            )
            .await,
    )
    .await;
    assert_eq!(later["autostart"], true, "an unrelated save keeps it");
    assert_eq!(later["privilege"], "root", "and applies what it did name");
    assert_eq!(settings_file(&server)["autostart"], true);

    // And it can be turned off again, by the field alone.
    let off = body(
        server
            .put_json(
                MODULE,
                json!({"config": "default", "privilege": "root", "autostart": false}),
            )
            .await,
    )
    .await;
    assert_eq!(off["autostart"], false);
    assert!(
        settings_file(&server).get("autostart").is_none(),
        "off is not written at all"
    );
}

#[tokio::test]
async fn a_version_a_request_does_not_name_is_kept() {
    let server = Server::start().await;
    install(&server);

    // Choose a version, which is the only way one is ever set.
    let chosen = body(
        server
            .put_json(
                MODULE,
                json!({"version": "1.14.2", "config": "default", "privilege": "operator"}),
            )
            .await,
    )
    .await;
    assert_eq!(chosen["version"], "1.14.2");

    // A save that picks something else about the module says nothing about the
    // version, and must not drop it.
    let later = body(
        server
            .put_json(
                MODULE,
                json!({"config": "default", "privilege": "root", "autostart": true}),
            )
            .await,
    )
    .await;
    assert_eq!(later["version"], "1.14.2", "kept, not cleared");
    assert_eq!(settings_file(&server)["version"], "1.14.2", "on disk");

    // Saying `null` is how a caller clears it on purpose.
    let cleared = body(
        server
            .put_json(
                MODULE,
                json!({"version": null, "config": "default", "privilege": "root"}),
            )
            .await,
    )
    .await;
    assert_eq!(cleared["version"], Value::Null);
    assert!(settings_file(&server).get("version").is_none(), "on disk");
}

/// An installed version's binary, so a chosen version is one that exists.
fn install(server: &Server) {
    use std::os::unix::fs::PermissionsExt;
    use suba_singbox::core::{Dirs, Metadata, Version};

    let dirs = Dirs::new(server.root.join("data"));
    let version = Version::from_tag("1.14.2");
    let schema = json!({"type": "object", "properties": {}, "additionalProperties": true});
    let metadata = Metadata {
        version: version.clone(),
        tag: version.tag(),
        asset: "fixture.tar.gz".to_owned(),
        platform: "fixture".to_owned(),
        asset_sha256: "fixture".to_owned(),
        binary_sha256: "fixture".to_owned(),
        schema_sha256: suba_singbox::core::sha256_hex(&serde_json::to_vec(&schema).unwrap()),
        installed_at: 1_700_000_000,
    };
    std::fs::create_dir_all(dirs.binary(&version).parent().unwrap()).unwrap();
    std::fs::write(
        dirs.metadata(&version),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    std::fs::write(dirs.schema(&version), serde_json::to_vec(&schema).unwrap()).unwrap();
    std::fs::write(dirs.binary(&version), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        dirs.binary(&version),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}
