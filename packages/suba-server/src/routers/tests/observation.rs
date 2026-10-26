use super::*;

#[tokio::test]
async fn observations_require_auth_and_distinguish_stopped_from_zero_traffic() {
    let server = Server::start().await;
    for resource in ["metrics", "connections"] {
        let path = format!("/api/cores/sing-box/{resource}?user=alice&inbound=vless-in");
        assert_eq!(server.get(&path).send().await.unwrap().status(), 401);
        let response = server
            .authed(reqwest::Method::GET, &path)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let value = body(response).await;
        assert_eq!(value["state"], "stopped");
        assert_eq!(value["gap"], false);
        assert!(value.get("run_id").is_none());
        if resource == "metrics" {
            assert!(value["totals"].is_null());
            assert_eq!(value["groups"], json!([]));
        } else {
            assert_eq!(value["connections"], json!([]));
        }
    }
}
