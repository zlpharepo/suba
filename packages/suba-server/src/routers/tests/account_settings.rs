use http::header;
use serde_json::json;

use super::{body, Server};

#[tokio::test]
async fn signing_out_other_sessions_keeps_the_current_login() {
    let server = Server::start().await;
    let mut other_tokens = Vec::new();
    for _ in 0..2 {
        let login = server
            .client
            .post(format!("{}/api/auth/password", server.base))
            .header(header::CONTENT_TYPE, "application/json")
            .body(json!({"username": "example-admin", "password": "example-password"}).to_string())
            .send()
            .await
            .unwrap();
        other_tokens.push(
            body(login).await["access_token"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }

    let anonymous = server
        .client
        .delete(format!("{}/api/auth/sessions/others", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);

    let revoked = server
        .authed(reqwest::Method::DELETE, "/api/auth/sessions/others")
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 204);

    let current = server
        .authed(reqwest::Method::GET, "/api/account")
        .send()
        .await
        .unwrap();
    assert_eq!(current.status(), 200);
    for token in other_tokens {
        let other = server
            .client
            .get(format!("{}/api/account", server.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), 401);
    }
}

#[tokio::test]
async fn an_account_password_change_requires_the_current_password_and_invalidates_all_sessions() {
    let server = Server::start().await;
    let second = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "example-admin", "password": "example-password"}).to_string())
        .send()
        .await
        .unwrap();
    let second_token = body(second).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let account = server
        .authed(reqwest::Method::GET, "/api/account")
        .send()
        .await
        .unwrap();
    assert_eq!(account.status(), 200);
    assert_eq!(body(account).await, json!({"username": "example-admin"}));

    let wrong = server
        .put_json(
            "/api/account/password",
            json!({"current_password": "incorrect", "new_password": "new-example-password"}),
        )
        .await;
    assert_eq!(wrong.status(), 422);

    let changed = server
        .put_json(
            "/api/account/password",
            json!({"current_password": "example-password", "new_password": "new-example-password"}),
        )
        .await;
    assert_eq!(changed.status(), 204);

    for token in [&server.token, &second_token] {
        let old = server
            .client
            .get(format!("{}/api/account", server.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(old.status(), 401);
    }

    let old_login = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "example-admin", "password": "example-password"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(old_login.status(), 401);
    let new_login = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "example-admin", "password": "new-example-password"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(new_login.status(), 201);
}

#[tokio::test]
async fn a_username_change_preserves_the_password_and_revokes_existing_sessions() {
    let server = Server::start().await;
    let second = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "example-admin", "password": "example-password"}).to_string())
        .send()
        .await
        .unwrap();
    let second_token = body(second).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let wrong = server
        .put_json(
            "/api/account",
            json!({"username": "renamed-admin", "current_password": "incorrect"}),
        )
        .await;
    assert_eq!(wrong.status(), 422);
    let unchanged = server
        .authed(reqwest::Method::GET, "/api/account")
        .send()
        .await
        .unwrap();
    assert_eq!(body(unchanged).await, json!({"username": "example-admin"}));

    let changed = server
        .put_json(
            "/api/account",
            json!({"username": "renamed-admin", "current_password": "example-password"}),
        )
        .await;
    assert_eq!(changed.status(), 204);
    for token in [&server.token, &second_token] {
        let old = server
            .client
            .get(format!("{}/api/account", server.base))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(old.status(), 401);
    }

    let old_login = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "example-admin", "password": "example-password"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(old_login.status(), 401);
    let new_login = server
        .client
        .post(format!("{}/api/auth/password", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({"username": "renamed-admin", "password": "example-password"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(new_login.status(), 201);
}

#[tokio::test]
async fn changing_the_subscription_prefix_replaces_delivery_paths_without_changing_tokens() {
    let server = Server::start().await;
    let token = server.delivery().await;
    let settings = server
        .authed(reqwest::Method::GET, "/api/system/settings")
        .send()
        .await
        .unwrap();
    assert_eq!(settings.status(), 200);
    assert_eq!(body(settings).await, json!({"subscription_prefix": "s"}));

    let invalid = server
        .put_json(
            "/api/system/settings",
            json!({"subscription_prefix": "api"}),
        )
        .await;
    assert_eq!(invalid.status(), 422);
    let changed = server
        .put_json(
            "/api/system/settings",
            json!({"subscription_prefix": "feed"}),
        )
        .await;
    assert_eq!(changed.status(), 200);
    assert_eq!(body(changed).await, json!({"subscription_prefix": "feed"}));

    let old = server
        .get(&format!("/s/phone/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 404);
    let new = server
        .get(&format!("/feed/phone/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(new.status(), 200);
    let listed = server
        .authed(reqwest::Method::GET, "/api/collections/main/tokens")
        .send()
        .await
        .unwrap();
    assert_eq!(
        body(listed).await[0]["path"],
        format!("/feed/phone/{token}")
    );

    let anonymous = server.get("/api/system/settings").send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
}
