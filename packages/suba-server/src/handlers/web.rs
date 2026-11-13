//! Installation of the separately released Web build into the instance data directory.

use std::{io::Cursor, path::Component, time::Duration};

use axum::{
    extract::{FromRequestParts, Request, State},
    Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    dto::{Authenticated, ResponseResult},
    AppState, Error,
};

const RELEASE: &str = "https://api.github.com/repos/zlpharepo/suba-web/releases/latest";
const ASSETS: &str = "https://github.com/zlpharepo/suba-web/releases/download";
const MAX_ARCHIVE: usize = 32 * 1024 * 1024;
const MAX_UNPACKED: u64 = 64 * 1024 * 1024;

#[derive(Serialize)]
pub struct WebStatus {
    installed_version: Option<String>,
    latest_version: Option<String>,
}

fn release_error(reason: &'static str) -> Error {
    Error::WebRelease { reason }
}

async fn latest(state: &AppState) -> ResponseResult<String> {
    let fetch = async {
        let response = state
            .http()
            .get(RELEASE)
            .send()
            .await
            .map_err(|_| release_error("release lookup failed"))?;
        if !response.status().is_success() {
            return Err(release_error("release lookup failed"));
        }
        response
            .text()
            .await
            .map_err(|_| release_error("invalid release metadata"))
    };
    let metadata = tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .map_err(|_| release_error("release lookup timed out"))??;
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata).map_err(|_| release_error("invalid release metadata"))?;
    let tag = metadata["tag_name"]
        .as_str()
        .ok_or_else(|| release_error("invalid release tag"))?;
    let version = tag
        .strip_prefix('v')
        .ok_or_else(|| release_error("invalid release tag"))?;
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(release_error("invalid release tag"));
    }
    let assets = metadata["assets"]
        .as_array()
        .ok_or_else(|| release_error("missing release assets"))?;
    for name in ["suba-web.tar.gz", "suba-web.tar.gz.sha256"] {
        if !assets.iter().any(|asset| asset["name"] == name) {
            return Err(release_error("missing release assets"));
        }
    }
    Ok(version.to_string())
}

async fn download(state: &AppState, url: &str, limit: usize) -> ResponseResult<Vec<u8>> {
    let fetch = async {
        let mut response = state
            .http()
            .get(url)
            .send()
            .await
            .map_err(|_| release_error("asset download failed"))?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > limit as u64)
        {
            return Err(release_error("asset download failed"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| release_error("asset download failed"))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(release_error("asset exceeds size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    };
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .map_err(|_| release_error("asset download timed out"))?
}

fn verify_archive(bytes: &[u8], checksum: &[u8]) -> ResponseResult<()> {
    let expected = std::str::from_utf8(checksum)
        .map_err(|_| release_error("invalid checksum"))?
        .split_whitespace()
        .next()
        .ok_or_else(|| release_error("invalid checksum"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(release_error("invalid checksum"));
    }
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(release_error("checksum mismatch"));
    }
    Ok(())
}

fn unpack(bytes: Vec<u8>, stage: &std::path::Path, version: &str) -> ResponseResult<()> {
    std::fs::create_dir_all(stage)?;
    let result = (|| {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        let mut total = 0_u64;
        let mut count = 0;
        for entry in archive
            .entries()
            .map_err(|_| release_error("invalid archive"))?
        {
            let mut entry = entry.map_err(|_| release_error("invalid archive"))?;
            count += 1;
            if count > 4096 {
                return Err(release_error("archive has too many files"));
            }
            let path = entry
                .path()
                .map_err(|_| release_error("invalid archive path"))?;
            if !path
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
            {
                return Err(release_error("invalid archive path"));
            }
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_dir() {
                return Err(release_error("unsupported archive entry"));
            }
            total = total.saturating_add(
                entry
                    .header()
                    .size()
                    .map_err(|_| release_error("invalid archive"))?,
            );
            if total > MAX_UNPACKED {
                return Err(release_error("archive exceeds size limit"));
            }
            if !entry
                .unpack_in(stage)
                .map_err(|_| release_error("invalid archive"))?
            {
                return Err(release_error("invalid archive path"));
            }
        }
        if !stage.join("index.html").is_file() {
            return Err(release_error("archive has no index page"));
        }
        std::fs::write(stage.join(".suba-version"), version)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(stage);
    }
    result
}

async fn installed_version(state: &AppState) -> Option<String> {
    tokio::fs::read_to_string(state.web_dir().join(".suba-version"))
        .await
        .ok()
        .map(|version| version.trim().to_string())
}

/// Current and published Web versions for the local instance.
pub async fn status(State(state): State<AppState>) -> Json<WebStatus> {
    let mut cached = state.web_release().lock().await;
    let published = match cached.as_ref() {
        Some((checked, value))
            if checked.elapsed() < Duration::from_secs(if value.is_some() { 300 } else { 60 }) =>
        {
            value.clone()
        }
        _ => {
            let value = latest(&state).await.ok();
            *cached = Some((std::time::Instant::now(), value.clone()));
            value
        }
    };
    Json(WebStatus {
        installed_version: installed_version(&state).await,
        latest_version: published,
    })
}

/// The fixed-source first install is available without a browser session.
pub async fn install(
    State(state): State<AppState>,
    request: Request,
) -> ResponseResult<Json<WebStatus>> {
    let _guard = state.web_lock().lock().await;
    if state.web_dir().join("index.html").is_file() {
        let (mut parts, _) = request.into_parts();
        Authenticated::from_request_parts(&mut parts, &state).await?;
    }
    let version = latest(&state).await?;
    let release = format!("{ASSETS}/v{version}/suba-web.tar.gz");
    let archive = download(&state, &release, MAX_ARCHIVE).await?;
    let checksum = download(&state, &format!("{release}.sha256"), 256).await?;
    verify_archive(&archive, &checksum)?;
    let web = state.web_dir();
    let parent = web
        .parent()
        .ok_or_else(|| release_error("invalid data directory"))?;
    let nonce = uuid::Uuid::now_v7();
    let stage = parent.join(format!("web-stage-{nonce}"));
    let backup = parent.join(format!("web-backup-{nonce}"));
    tokio::task::spawn_blocking({
        let stage = stage.clone();
        let version = version.clone();
        move || unpack(archive, &stage, &version)
    })
    .await??;
    if web.exists() {
        std::fs::rename(&web, &backup)?;
    }
    if let Err(error) = std::fs::rename(&stage, &web) {
        if backup.exists() {
            if let Err(restore) = std::fs::rename(&backup, &web) {
                crate::tracing::error!(kind = ?restore.kind(), "previous web directory could not be restored");
            }
        }
        let _ = std::fs::remove_dir_all(&stage);
        return Err(error.into());
    }
    if backup.exists() {
        if let Err(error) = std::fs::remove_dir_all(backup) {
            crate::tracing::warn!(kind = ?error.kind(), "previous web directory could not be removed");
        }
    }
    Ok(Json(WebStatus {
        installed_version: Some(version.clone()),
        latest_version: Some(version),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_archive_installs_a_root_page_and_version() {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut root = tar::Header::new_gnu();
        root.set_path("./").unwrap();
        root.set_entry_type(tar::EntryType::Directory);
        root.set_size(0);
        root.set_cksum();
        archive.append(&root, std::io::empty()).unwrap();
        let mut page = tar::Header::new_gnu();
        page.set_path("./index.html").unwrap();
        page.set_size(5);
        page.set_cksum();
        archive.append(&page, Cursor::new(b"hello")).unwrap();
        let encoder = archive.into_inner().unwrap();
        let bytes = encoder.finish().unwrap();
        let root = std::env::temp_dir().join(format!("suba-web-test-{}", uuid::Uuid::now_v7()));
        unpack(bytes.clone(), &root, "0.1.0").unwrap();
        assert_eq!(std::fs::read(root.join("index.html")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read_to_string(root.join(".suba-version")).unwrap(),
            "0.1.0"
        );
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        verify_archive(&bytes, format!("{hash}  suba-web.tar.gz\n").as_bytes()).unwrap();
        assert!(verify_archive(
            &bytes,
            format!("{}  suba-web.tar.gz\n", "0".repeat(64)).as_bytes()
        )
        .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
