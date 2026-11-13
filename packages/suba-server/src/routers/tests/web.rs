use serde_json::json;

use super::{body, Server};

#[tokio::test]
async fn missing_web_has_an_install_homepage_and_a_status_resource() {
    let server = Server::start().await;
    let page = server.get("/").send().await.unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("Install Web"));
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
