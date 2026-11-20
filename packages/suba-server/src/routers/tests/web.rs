use serde_json::json;

use super::{body, Server};

#[tokio::test]
async fn missing_web_has_an_install_homepage_and_a_status_resource() {
    let server = Server::start().await;
    let page = server.get("/").send().await.unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("Install Web"));
    assert!(html.contains(r#"accept=".gz,.tgz""#));
    assert!(html.contains("/api/system/web"));

    let status = server.get("/api/system/web").send().await.unwrap();
    assert_eq!(status.status(), 200);
    assert_eq!(body(status).await["installed_version"], json!(null));
}

#[tokio::test]
async fn installed_web_update_requires_a_session() {
    let server = Server::start().await;
    let web = server.root.join("data/web");
    crate::fs::ensure_dir(&web).unwrap();
    std::fs::write(web.join("index.html"), "installed web").unwrap();
    let update = server
        .client
        .post(format!("{}/api/system/web", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 401);
}

#[tokio::test]
async fn github_mirror_serves_release_metadata_and_downloads_without_the_token() {
    use axum::{
        http::{header, HeaderMap, StatusCode, Uri},
        response::IntoResponse as _,
        Json, Router,
    };

    let page = b"mirrored web";
    let archive = archive(&[("index.html", page)]);
    let checksum = suba_core::checksum::sha256_hex(&archive);

    #[cfg(feature = "singbox-core")]
    let asset_requested = std::sync::Arc::new(tokio::sync::Notify::new());
    #[cfg(feature = "singbox-core")]
    let asset_signal = asset_requested.clone();
    let routes = Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
        let archive = archive.clone();
        let checksum = checksum.clone();
        #[cfg(feature = "singbox-core")]
        let asset_signal = asset_signal.clone();
        async move {
            if headers.contains_key(header::AUTHORIZATION) {
                return StatusCode::FORBIDDEN.into_response();
            }
            match uri.path() {
                "/mirror/https://api.github.com/repos/zlpharepo/suba-web/releases/latest" => {
                    Json(json!({
                        "tag_name": "v1.2.3",
                        "assets": [{"name": "suba-web.tar.gz"}, {"name": "suba-web.tar.gz.sha256"}],
                    }))
                    .into_response()
                }
                "/mirror/https://github.com/zlpharepo/suba-web/releases/download/v1.2.3/suba-web.tar.gz" => {
                    archive.into_response()
                }
                "/mirror/https://github.com/zlpharepo/suba-web/releases/download/v1.2.3/suba-web.tar.gz.sha256" => {
                    checksum.into_response()
                }
                #[cfg(feature = "singbox-core")]
                "/mirror/https://api.github.com/repos/SagerNet/sing-box/releases"
                    if uri.query() == Some("per_page=30") =>
                {
                    let platform = suba_singbox::core::platform().unwrap();
                    Json(json!([{
                        "tag_name": "v1.14.3",
                        "assets": [{
                            "name": format!("sing-box-1.14.3-{platform}.tar.gz"),
                            "browser_download_url": "https://github.com/example/project/releases/download/v1.14.3/fixture",
                            "size": 1,
                        }],
                    }]))
                    .into_response()
                }
                #[cfg(feature = "singbox-core")]
                "/mirror/https://github.com/example/project/releases/download/v1.14.3/fixture" => {
                    asset_signal.notify_one();
                    StatusCode::BAD_GATEWAY.into_response()
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefix = format!("http://{}/mirror/", listener.local_addr().unwrap());
    let mirror = tokio::spawn(async move { axum::serve(listener, routes).await });

    let server = Server::start().await;
    let saved = server
        .put_json(
            "/api/system/settings",
            json!({"github_mirror": prefix, "github_token": "fixture-token"}),
        )
        .await;
    assert_eq!(saved.status(), 200);

    let status = server.get("/api/system/web").send().await.unwrap();
    assert_eq!(body(status).await["latest_version"], "1.2.3");
    let install = server
        .authed(reqwest::Method::POST, "/api/system/web")
        .send()
        .await
        .unwrap();
    assert_eq!(install.status(), 200, "{}", body(install).await);
    assert_eq!(
        std::fs::read(server.root.join("data/web/index.html")).unwrap(),
        page
    );

    #[cfg(feature = "singbox-core")]
    {
        let listed = server
            .authed(reqwest::Method::GET, "/api/cores/sing-box/releases")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), 200);
        assert_eq!(body(listed).await["latest"], "1.14.3");
        let install = server
            .authed(reqwest::Method::POST, "/api/cores/sing-box/versions/1.14.3")
            .send()
            .await
            .unwrap();
        assert_eq!(install.status(), 202);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            asset_requested.notified(),
        )
        .await
        .expect("the archive request reaches the configured mirror");
    }

    mirror.abort();
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut bundle = tar::Builder::new(encoder);
    for &(name, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(content.len() as u64);
        header.set_cksum();
        bundle.append_data(&mut header, name, content).unwrap();
    }
    bundle.into_inner().unwrap().finish().unwrap()
}

#[tokio::test]
async fn web_upload_requires_authentication_and_installs_without_a_release_lookup() {
    let server = Server::start().await;
    let page = server.get("/").send().await.unwrap().text().await.unwrap();
    assert!(page.contains("Upload Web"));

    let path = "/api/system/web";
    let upload = archive(&[("index.html", b"uploaded web")]);
    let denied = server
        .client
        .put(format!("{}{path}", server.base))
        .header(http::header::CONTENT_TYPE, "application/gzip")
        .body(upload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);

    let saved = server
        .authed(reqwest::Method::PUT, &format!("{path}?version=v1.2.3"))
        .header(http::header::CONTENT_TYPE, "application/gzip")
        .body(upload)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 200);
    assert_eq!(body(saved).await["installed_version"], "1.2.3");

    let refused = server
        .authed(reqwest::Method::PUT, path)
        .header(http::header::CONTENT_TYPE, "application/gzip")
        .body(archive(&[("assets/fixture", b"no root page")]))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let page = server.get("/").send().await.unwrap().text().await.unwrap();
    assert_eq!(page, "uploaded web");

    let unversioned = server
        .authed(reqwest::Method::PUT, path)
        .header(http::header::CONTENT_TYPE, "application/gzip")
        .body(archive(&[("index.html", b"updated web")]))
        .send()
        .await
        .unwrap();
    assert_eq!(unversioned.status(), 200);
    assert!(body(unversioned).await["installed_version"].is_null());
    assert!(!server.root.join("data/web/.suba-version").exists());
    assert_eq!(
        server.get("/").send().await.unwrap().text().await.unwrap(),
        "updated web"
    );
}

#[cfg(feature = "singbox-core")]
#[tokio::test]
async fn core_upload_installs_an_archive_without_a_release_lookup() {
    let server = Server::start().await;
    let versions = "/api/cores/sing-box/versions";
    let platform = suba_singbox::core::platform().unwrap();
    let name = format!("sing-box-1.14.99-{platform}.tar.gz");
    let file = archive(&[
        ("release/sing-box", b"#!/bin/sh\ncase \"$1\" in\nversion) printf '1.14.99\\n';;\nschema) printf '{}' > \"$3\";;\n*) exit 1;;\nesac\n"),
        ("release/LICENSE", b"fixture license"),
    ]);
    let post = |name: &str| {
        server
            .authed(
                reqwest::Method::POST,
                &format!("{versions}?filename={name}"),
            )
            .header(http::header::CONTENT_TYPE, "application/gzip")
            .body(file.clone())
    };

    let refused = post("sing-box-1.14.99-unknown-platform.tar.gz")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let accepted = post(&name).send().await.unwrap();
    assert_eq!(accepted.status(), 202);
    let state = body(accepted).await;
    assert_eq!(state["version"], "1.14.99");

    async fn completed(server: &Server, path: &str) -> serde_json::Value {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let current = server
                    .authed(reqwest::Method::GET, path)
                    .send()
                    .await
                    .unwrap();
                let current = body(current).await;
                if current["installation"]["status"] != "downloading" {
                    break current;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }
    let installed = completed(&server, &format!("{versions}/1.14.99")).await;
    assert_eq!(installed["installation"]["status"], "installed");
    assert_eq!(installed["current"], true);
    assert_eq!(post(&name).send().await.unwrap().status(), 200);

    let wrong_version = format!("sing-box-1.14.98-{platform}.tar.gz");
    let pending = post(&wrong_version).send().await.unwrap();
    assert_eq!(pending.status(), 202);
    let failed = completed(&server, &format!("{versions}/1.14.98")).await;
    assert_eq!(failed["installation"]["status"], "failed");
    assert_eq!(
        failed["installation"]["error"],
        "the binary version does not match the archive name"
    );
    assert!(!server.root.join("data/sing-box/versions/1.14.98").exists());
}
