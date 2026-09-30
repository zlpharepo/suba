//! Putting a version on this machine, and taking one off.
//!
//! An install is one operation with one outcome: either the version is there,
//! complete — binary, licence, its own schema, and the record of what was
//! measured — or nothing has changed at all. It gets there by unpacking into a
//! directory beside the final one, asking the unpacked binary to write its
//! schema there, and only then renaming that directory into place. A rename
//! within one directory is the moment the version appears; there is no in
//! between state for anything else to read.
//!
//! **What the record is.** Facts only, and each of them measured here or given
//! by whoever published the release: the bytes of the archive, of the binary,
//! and of the schema. The schema is the binary's own output — `sing-box schema`
//! — so "this version's grammar" is not a claim about the version, it is the
//! version.
//!
//! **What a caller has to bring.** The archive's bytes, the digest it was
//! published with (the release API carries one), the clock, and — for the two
//! functions that use the network — an HTTP client and a URL. Nothing here looks
//! a URL up on its own or reads a clock, so every one of these can be exercised
//! without a network and at a fixed time.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::{extract, sha256_hex, Dirs, Error, Metadata, Release, Version};

/// The name the binary has inside a release archive, and the name it keeps.
const BINARY: &str = "sing-box";

/// The licence that travels beside it.
const LICENSE: &str = "LICENSE";

/// How large an asset may be before this build stops reading it.
///
/// A released archive for one platform is tens of megabytes; the cap is what
/// keeps a mistyped URL or a hostile answer from filling memory.
pub const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;

/// Install a version from the bytes of its release archive.
///
/// `expected` is the sha256 the release was published with, when there is one:
/// the archive is refused unless it hashes to exactly that. `now` is the clock,
/// passed in rather than read.
///
/// The version is refused if it is already installed — a caller that wants
/// installing to be idempotent checks first, so that "already there" can be
/// answered without downloading anything.
pub fn install(
    dirs: &Dirs,
    version: &Version,
    platform: &str,
    asset: &str,
    archive: &[u8],
    expected: Option<&str>,
    now: i64,
) -> Result<Metadata, Error> {
    if dirs.metadata(version).exists() {
        return Err(Error::Installed {
            version: version.clone(),
        });
    }

    let asset_sha256 = sha256_hex(archive);
    if let Some(expected) = expected {
        if expected != asset_sha256 {
            return Err(Error::Hash {
                expected: expected.to_string(),
                found: asset_sha256,
            });
        }
    }

    let extracted = extract(archive)?;
    let binary_sha256 = sha256_hex(&extracted.binary);

    let staging = stage(dirs, version);

    // One operation with one outcome: whatever fails inside here, nothing of the
    // half-built version is left beside the ones that work.
    let built = (|| -> Result<Metadata, Error> {
        let bin = staging.join("bin");
        create_dir(&bin, "the version's own directory")?;

        write(&bin.join(BINARY), &extracted.binary, true)?;
        write(&bin.join(LICENSE), &extracted.license, false)?;

        let schema = staging.join("schema.json");
        let metadata = Metadata {
            version: version.clone(),
            tag: version.tag(),
            asset: asset.to_string(),
            platform: platform.to_string(),
            asset_sha256,
            binary_sha256,
            schema_sha256: generate_schema(&bin.join(BINARY), &schema)?,
            installed_at: now,
        };

        let record = serde_json::to_vec_pretty(&metadata).map_err(|_| Error::Files {
            at: "the version's record",
            reason: "it does not serialise",
        })?;
        write(&staging.join("metadata.json"), &record, false)?;

        // The version appears here, and only here.
        fs::rename(&staging, dirs.version(version)).map_err(|error| Error::Files {
            at: "putting the version in place",
            reason: reason_of(&error),
        })?;

        Ok(metadata)
    })();

    if built.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }

    built
}

/// Where a version is built before it exists.
///
/// Beside the versions rather than anywhere else, because a rename only replaces
/// what it can reach in one directory.
fn stage(dirs: &Dirs, version: &Version) -> PathBuf {
    dirs.versions().join(format!(
        ".{}.{}-staging",
        version.as_str(),
        std::process::id()
    ))
}

/// Ask a binary to write its own schema, and measure what it wrote.
fn generate_schema(binary: &Path, schema: &Path) -> Result<String, Error> {
    let ran = Command::new(binary)
        .arg("schema")
        .arg("-o")
        .arg(schema)
        .output()
        .map_err(|_| Error::Run {
            reason: "the binary could not be started",
        })?;

    if !ran.status.success() {
        return Err(Error::Run {
            reason: "the binary did not write its schema",
        });
    }

    let generated = fs::read(schema).map_err(|error| Error::Files {
        at: "the schema the binary wrote",
        reason: reason_of(&error),
    })?;

    Ok(sha256_hex(&generated))
}

/// The versions this machine has, oldest name first.
///
/// Read from the directories and their records, without running anything: a
/// version whose record cannot be read is reported rather than left out, because
/// an installed version that quietly does not appear is a version someone will
/// install twice.
pub fn installed(dirs: &Dirs) -> Result<Vec<Metadata>, Error> {
    let listing = match fs::read_dir(dirs.versions()) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::Files {
                at: "listing the installed versions",
                reason: reason_of(&error),
            })
        }
    };

    let mut versions = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|error| Error::Files {
            at: "listing the installed versions",
            reason: reason_of(&error),
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // A staging directory is an install that did not finish.
        if name.starts_with('.') {
            continue;
        }

        let record = entry.path().join("metadata.json");
        let bytes = fs::read(&record).map_err(|error| Error::Record {
            version: name.clone(),
            reason: match error.kind() {
                std::io::ErrorKind::NotFound => "there is no record",
                _ => "the record cannot be read",
            },
        })?;
        let metadata: Metadata = serde_json::from_slice(&bytes).map_err(|_| Error::Record {
            version: name.clone(),
            reason: "the record is not a record",
        })?;

        versions.push(metadata);
    }

    versions.sort_by(|one, other| one.version.cmp(&other.version));

    Ok(versions)
}

/// Remove an installed version.
///
/// Which version is in use is the caller's record, not this crate's; it passes
/// that version as `current`, and removing it is refused: the version a machine
/// falls back to is taken away only after switching.
pub fn uninstall(dirs: &Dirs, version: &Version, current: Option<&Version>) -> Result<(), Error> {
    if !dirs.metadata(version).exists() {
        return Err(Error::NotInstalled {
            version: version.clone(),
        });
    }
    if current == Some(version) {
        return Err(Error::Current {
            version: version.clone(),
        });
    }

    fs::remove_dir_all(dirs.version(version)).map_err(|error| Error::Files {
        at: "removing the version",
        reason: reason_of(&error),
    })
}

/// What a release server lists.
///
/// The URL is the caller's: this crate knows the shape of what GitHub's release
/// API answers, not where to find it.
pub async fn releases(client: &reqwest::Client, url: &str) -> Result<Vec<Release>, Error> {
    let answer = client.get(url).send().await.map_err(|_| Error::Network {
        reason: "the release server could not be reached",
    })?;

    let status = answer.status();
    if !status.is_success() {
        return Err(refused(status.as_u16()));
    }

    let body = answer.bytes().await.map_err(|_| Error::Network {
        reason: "the release listing stopped part way",
    })?;

    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Error::Release {
        field: "the listing",
    })?;
    let listed = value.as_array().ok_or(Error::Release {
        field: "the listing",
    })?;

    listed.iter().map(Release::from_json).collect()
}

/// The bytes of one release asset.
pub async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, Error> {
    download_with_progress(client, url, |_, _| {}).await
}

/// Download an asset, reporting bytes received and the declared total if known.
pub async fn download_with_progress(
    client: &reqwest::Client,
    url: &str,
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, Error> {
    let mut answer = client.get(url).send().await.map_err(|_| Error::Network {
        reason: "the release server could not be reached",
    })?;

    let status = answer.status();
    if !status.is_success() {
        return Err(refused(status.as_u16()));
    }

    if answer
        .content_length()
        .is_some_and(|length| length > MAX_ASSET_BYTES)
    {
        return Err(Error::Archive {
            reason: "the asset is larger than this build reads",
        });
    }

    let total = answer.content_length();
    let mut body = Vec::new();
    progress(0, total);

    while let Some(chunk) = answer.chunk().await.map_err(|_| Error::Network {
        reason: "the download stopped part way",
    })? {
        if body.len() as u64 + chunk.len() as u64 > MAX_ASSET_BYTES {
            return Err(Error::Archive {
                reason: "the asset is larger than this build reads",
            });
        }

        body.extend_from_slice(&chunk);
        progress(body.len() as u64, total);
    }

    Ok(body)
}

/// What a caller may ask the core to generate.
///
/// A whitelist, and not one the core enforces: measured on 1.14.2,
/// `sing-box generate <anything>` **exits 0** and prints its usage, so a build
/// that passed a caller's string through would report success for a command that
/// never ran. Every argument below is this module's, never the caller's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum Generate {
    /// `generate ech-keypair <server name>`
    #[serde(rename = "ech-keypair")]
    EchKeyPair,
    /// `generate rand [--hex] <length>`
    #[serde(rename = "rand")]
    Rand,
    /// `generate reality-keypair`
    #[serde(rename = "reality-keypair")]
    RealityKeyPair,
    /// `generate tls-keypair <server name>`
    #[serde(rename = "tls-keypair")]
    TlsKeyPair,
    /// `generate uuid`
    #[serde(rename = "uuid")]
    Uuid,
    /// `generate vapid-keypair`
    #[serde(rename = "vapid-keypair")]
    VapidKeyPair,
    /// `generate wg-keypair`
    #[serde(rename = "wg-keypair")]
    WgKeyPair,
}

impl Generate {
    /// The subcommand, as the core spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Generate::EchKeyPair => "ech-keypair",
            Generate::Rand => "rand",
            Generate::RealityKeyPair => "reality-keypair",
            Generate::TlsKeyPair => "tls-keypair",
            Generate::Uuid => "uuid",
            Generate::VapidKeyPair => "vapid-keypair",
            Generate::WgKeyPair => "wg-keypair",
        }
    }

    /// What it needs beside its own name.
    pub fn needs(self) -> Needs {
        match self {
            Generate::EchKeyPair | Generate::TlsKeyPair => Needs::Name,
            Generate::Rand => Needs::Length,
            _ => Needs::Nothing,
        }
    }
}

/// What a subcommand needs from a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    Nothing,
    /// A name the certificate or the ECH configuration is for.
    Name,
    /// How many bytes of randomness to generate.
    Length,
}

/// The longest name this build passes on: a host name cannot be longer.
const MAX_NAME: usize = 253;

/// The most randomness this build asks for: a core printing more than this on
/// one call is not something a request should be able to do.
const MAX_LENGTH: u32 = 4096;

/// Ask the installed binary for something it generates.
///
/// What comes back is a credential — a private key, a uuid — so it is handed to
/// the caller as it came and written nowhere else: not a log, not a file, and
/// never into an error. The caller names one of [`Generate`]; the arguments are
/// built here.
pub fn generate(
    dirs: &Dirs,
    version: &Version,
    kind: Generate,
    argument: Option<&str>,
) -> Result<String, Error> {
    let mut command = Command::new(dirs.binary(version));
    command.arg("generate").arg(kind.as_str());

    match kind.needs() {
        Needs::Nothing => {}
        Needs::Length => {
            let length = argument
                .and_then(|text| text.parse::<u32>().ok())
                .filter(|length| (1..=MAX_LENGTH).contains(length))
                .ok_or(Error::Generate {
                    command: kind.as_str(),
                    reason: "that is not a length this build asks for",
                })?;

            // Hex, because the text goes into a configuration and a mixture of
            // bytes would not: this is the one spelling of `rand` that is text.
            command.arg("--hex").arg(length.to_string());
        }
        Needs::Name => {
            let name = argument
                .filter(|name| {
                    !name.is_empty()
                        && name.len() <= MAX_NAME
                        && !name.starts_with('-')
                        && !name.contains('\0')
                        && !name.contains('\n')
                })
                .ok_or(Error::Generate {
                    command: kind.as_str(),
                    reason: "that is not a name this build passes on",
                })?;

            command.arg(name);
        }
    }

    let ran = command.output().map_err(|_| Error::Generate {
        command: kind.as_str(),
        reason: "the binary could not be started",
    })?;

    if !ran.status.success() {
        return Err(Error::Generate {
            command: kind.as_str(),
            reason: "the binary refused to generate anything",
        });
    }

    Ok(String::from_utf8_lossy(&ran.stdout).trim_end().to_string())
}

/// What to say about a status a release server answered with.
///
/// A `403` or `429` is usually a limit on this instance rather than a mistake in
/// the request, and saying so is the difference between a caller waiting and a
/// caller looking elsewhere. What this module cannot do is lift the limit, so
/// the hint does not pretend that it can.
fn refused(status: u16) -> Error {
    Error::Refused {
        status,
        hint: match status {
            403 | 429 => {
                "the release server is refusing requests from this instance, which is how it limits them"
            }
            _ => "the release server refused the request",
        },
    }
}

fn create_dir(path: &Path, at: &'static str) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|error| Error::Files {
        at,
        reason: reason_of(&error),
    })
}

fn write(path: &Path, bytes: &[u8], executable: bool) -> Result<(), Error> {
    fs::write(path, bytes).map_err(|error| Error::Files {
        at: "a file of the version",
        reason: reason_of(&error),
    })?;

    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| {
            Error::Files {
                at: "the binary's permissions",
                reason: reason_of(&error),
            }
        })?;
    }

    Ok(())
}

/// What went wrong, in a word.
///
/// The kind rather than the message: an `io::Error`'s own text carries the path
/// it was working on, and a path is a caller's detail rather than something an
/// error body should hand back.
fn reason_of(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as Kind;

    match error.kind() {
        Kind::NotFound => "it is not there",
        Kind::PermissionDenied => "it is not permitted",
        Kind::AlreadyExists => "it is already there",
        Kind::InvalidInput => "the name is not usable",
        _ => "the filesystem refused it",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Version;

    #[tokio::test]
    async fn a_download_reports_received_bytes_and_the_declared_total() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            tokio::task::yield_now().await;
            stream.write_all(b"67890").await.unwrap();
        });
        let mut progress = Vec::new();
        let body = download_with_progress(
            &reqwest::Client::new(),
            &format!("http://{address}/asset"),
            |downloaded, total| progress.push((downloaded, total)),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(body, b"1234567890");
        assert_eq!(progress.first(), Some(&(0, Some(10))));
        assert_eq!(progress.last(), Some(&(10, Some(10))));
    }

    /// A release archive with a binary that writes a schema when asked — the one
    /// thing an install needs a real binary for.
    fn archive(schema: &str) -> Vec<u8> {
        let binary = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = schema ] && [ \"$2\" = -o ]; then\n\
             \tprintf '%s' '{schema}' > \"$3\"\n\
             \texit 0\n\
             fi\n\
             exit 1\n"
        );

        members(&[
            ("release/sing-box", binary.as_bytes()),
            ("release/LICENSE", b"a licence"),
        ])
    }

    /// A release archive whose binary writes its schema and then does whatever
    /// the test told it to.
    fn archive_running(script: &str) -> Vec<u8> {
        let binary = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = schema ] && [ \"$2\" = -o ]; then\n\
             \tprintf '%s' '{{\"$defs\":{{}}}}' > \"$3\"\n\
             \texit 0\n\
             fi\n\
             {script}"
        );

        members(&[
            ("release/sing-box", binary.as_bytes()),
            ("release/LICENSE", b"a licence"),
        ])
    }

    /// Install a version whose binary runs `script` for anything but `schema`.
    fn install_script(dirs: &Dirs, script: &str) -> Version {
        let version = Version::from_tag("v1.14.2");

        install(
            dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive_running(script),
            None,
            1_700_000_000,
        )
        .expect("an install");

        version
    }

    /// A release archive with a binary that refuses to do anything.
    fn broken_archive() -> Vec<u8> {
        members(&[
            ("release/sing-box", b"#!/bin/sh\nexit 1\n"),
            ("release/LICENSE", b"a licence"),
        ])
    }

    fn members(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));

        for (name, bytes) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, std::io::Cursor::new(bytes))
                .expect("a member");
        }

        builder
            .into_inner()
            .expect("the encoder")
            .finish()
            .expect("gzip")
    }

    fn dirs() -> (Scratch, Dirs) {
        let scratch = Scratch::new();
        let dirs = Dirs::new(&scratch.0);

        (scratch, dirs)
    }

    /// A directory of this test's own, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static COUNTER: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "suba-singbox-install-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("a temporary directory");

            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn install_one(dirs: &Dirs, version: &str) {
        let version = Version::from_tag(version);

        install(
            dirs,
            &version,
            "linux-amd64",
            &format!("sing-box-{version}-linux-amd64.tar.gz"),
            &archive(r#"{"$defs":{}}"#),
            None,
            1_700_000_000,
        )
        .expect("an install");
    }

    #[test]
    fn a_release_lands_complete_and_says_what_it_measured() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");
        let metadata = install(
            &dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(r#"{"$defs":{}}"#),
            None,
            1_700_000_000,
        )
        .expect("an install");

        assert_eq!(metadata.version, version);
        assert_eq!(metadata.tag, "v1.14.2");
        assert_eq!(metadata.platform, "linux-amd64");
        assert_eq!(metadata.installed_at, 1_700_000_000);
        assert_eq!(
            metadata.asset_sha256,
            sha256_hex(&archive(r#"{"$defs":{}}"#))
        );
        assert_eq!(metadata.schema_sha256, sha256_hex(br#"{"$defs":{}}"#));

        let record: Metadata =
            serde_json::from_slice(&fs::read(dirs.metadata(&version)).expect("a record"))
                .expect("a readable record");
        assert_eq!(record, metadata);

        // The schema on disk is the one the record measured, and the binary is
        // the one that wrote it.
        assert_eq!(
            sha256_hex(&fs::read(dirs.schema(&version)).expect("a schema")),
            metadata.schema_sha256
        );
        assert_eq!(
            sha256_hex(&fs::read(dirs.binary(&version)).expect("a binary")),
            metadata.binary_sha256
        );
        assert!(dirs.license(&version).exists());

        // Nothing half-built is left beside it.
        let names: Vec<String> = fs::read_dir(dirs.versions())
            .expect("the versions directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["1.14.2"]);
    }

    #[test]
    fn an_archive_that_does_not_hash_to_what_was_promised_leaves_nothing() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");
        let promised = sha256_hex(b"something else entirely");

        let refused = install(
            &dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(r#"{"$defs":{}}"#),
            Some(&promised),
            1_700_000_000,
        );

        assert_eq!(
            refused,
            Err(Error::Hash {
                expected: promised,
                found: sha256_hex(&archive(r#"{"$defs":{}}"#)),
            })
        );
        assert!(!dirs.version(&version).exists());
        assert!(!dirs.versions().exists());
    }

    /// A digest that matches is recorded as given: it came from whoever
    /// published the release, and it is the one a second install has to match.
    #[test]
    fn a_digest_that_matches_is_the_one_recorded() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");
        let archive = archive(r#"{"$defs":{}}"#);
        let digest = sha256_hex(&archive);

        let metadata = install(
            &dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive,
            Some(&digest),
            1_700_000_000,
        )
        .expect("an install");

        assert_eq!(metadata.asset_sha256, digest);
    }

    #[test]
    fn a_binary_that_will_not_write_its_schema_leaves_nothing() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");

        let refused = install(
            &dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &broken_archive(),
            None,
            1_700_000_000,
        );

        assert_eq!(
            refused,
            Err(Error::Run {
                reason: "the binary did not write its schema",
            })
        );
        assert!(!dirs.version(&version).exists());
        let left: Vec<String> = fs::read_dir(dirs.versions())
            .expect("the versions directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(left.is_empty(), "a failed install leaves nothing: {left:?}");
    }

    #[test]
    fn a_generate_command_is_named_the_way_the_binary_names_it() {
        // The wire name and the subcommand are the same word: a request says
        // what it wants run, and a name this enum misspells would be a name the
        // binary refuses at run time rather than one refused here. The list is
        // what `sing-box generate` answers to, read off the binary itself.
        let known = [
            "ech-keypair",
            "rand",
            "reality-keypair",
            "tls-keypair",
            "uuid",
            "vapid-keypair",
            "wg-keypair",
        ];
        let mut named = Vec::new();

        for kind in [
            Generate::EchKeyPair,
            Generate::Rand,
            Generate::RealityKeyPair,
            Generate::TlsKeyPair,
            Generate::Uuid,
            Generate::VapidKeyPair,
            Generate::WgKeyPair,
        ] {
            let wire = serde_json::to_string(kind.as_str()).expect("a string");

            assert_eq!(
                serde_json::from_str::<Generate>(&wire).unwrap_or_else(|_| panic!(
                    "{} is not a name this enum answers to",
                    kind.as_str()
                )),
                kind
            );
            named.push(kind.as_str());
        }

        named.sort_unstable();

        assert_eq!(named, known);
    }

    #[test]
    fn a_generate_command_says_what_the_core_printed() {
        let (_root, dirs) = dirs();
        let version = install_script(&dirs, "echo 'PrivateKey: abc'; echo 'PublicKey: def'\n");

        let printed =
            generate(&dirs, &version, Generate::RealityKeyPair, None).expect("a key pair");

        assert_eq!(printed, "PrivateKey: abc\nPublicKey: def");
    }

    #[test]
    fn a_generate_command_that_refuses_is_refused() {
        let (_root, dirs) = dirs();
        let version = install_script(&dirs, "exit 1\n");

        assert_eq!(
            generate(&dirs, &version, Generate::Uuid, None),
            Err(Error::Generate {
                command: "uuid",
                reason: "the binary refused to generate anything",
            })
        );
    }

    /// What these commands print is a credential, so a failure must not carry
    /// it — an error that quoted the output would put a private key in a log.
    #[test]
    fn what_a_generate_command_printed_is_not_in_what_it_failed_with() {
        const SENTINEL: &str = "SENTINELPRIVATEKEY";

        let (_root, dirs) = dirs();
        let version = install_script(
            &dirs,
            &format!(
                "echo '{SENTINEL}'; exit 1
"
            ),
        );
        let error = generate(&dirs, &version, Generate::RealityKeyPair, None)
            .expect_err("the script exits non-zero");
        let printed = error.to_string();

        assert!(
            !printed.contains(SENTINEL),
            "the failure quoted what was printed: {printed}"
        );
        assert_eq!(
            error,
            Error::Generate {
                command: "reality-keypair",
                reason: "the binary refused to generate anything",
            }
        );
    }

    /// The whole command line is this module's: what a caller may add is one
    /// length or one name, and neither is passed on unread.
    #[test]
    fn the_arguments_a_generate_command_takes_are_this_builds() {
        let (_root, dirs) = dirs();
        let version = install_script(&dirs, "printf '%s\\n' \"$@\"\n");

        let printed = generate(&dirs, &version, Generate::Rand, Some("8")).expect("randomness");
        assert_eq!(
            printed.lines().collect::<Vec<_>>(),
            ["generate", "rand", "--hex", "8"]
        );

        for refused in [Some("0"), Some("99999"), Some("8; rm -rf /"), None] {
            assert!(
                matches!(
                    generate(&dirs, &version, Generate::Rand, refused),
                    Err(Error::Generate {
                        command: "rand",
                        ..
                    })
                ),
                "rand takes a length, and only a length this build asks for: {refused:?}"
            );
        }

        let printed =
            generate(&dirs, &version, Generate::TlsKeyPair, Some("example.com")).expect("a name");
        assert_eq!(
            printed.lines().collect::<Vec<_>>(),
            ["generate", "tls-keypair", "example.com"]
        );

        for refused in [Some("--help"), Some(""), None] {
            assert!(
                matches!(
                    generate(&dirs, &version, Generate::TlsKeyPair, refused),
                    Err(Error::Generate {
                        command: "tls-keypair",
                        ..
                    })
                ),
                "tls-keypair takes one name, and not one that is really a flag: {refused:?}"
            );
        }

        // And one that takes nothing takes nothing, whatever a caller sends.
        let printed = generate(&dirs, &version, Generate::Uuid, Some("--version")).expect("a uuid");
        assert_eq!(printed.lines().collect::<Vec<_>>(), ["generate", "uuid"]);
    }

    #[test]
    fn installing_a_version_that_is_already_there_is_refused() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");
        install_one(&dirs, "v1.14.2");
        let before = fs::read(dirs.metadata(&version)).expect("the record");

        let refused = install(
            &dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(r#"{"$defs":{}}"#),
            None,
            1_700_000_001,
        );

        assert_eq!(refused, Err(Error::Installed { version }));
        assert_eq!(
            fs::read(dirs.metadata(&Version::from_tag("v1.14.2"))).expect("the record"),
            before
        );
    }

    #[test]
    fn the_versions_this_machine_has_are_listed_oldest_name_first() {
        let (_root, dirs) = dirs();
        install_one(&dirs, "v1.14.2");
        install_one(&dirs, "v1.13.9");
        install_one(&dirs, "v1.15.0-alpha.1");

        let listed = installed(&dirs).expect("the installed versions");
        let names: Vec<&str> = listed
            .iter()
            .map(|metadata| metadata.version.as_str())
            .collect();

        // An alpha sorts before the release it precedes, and 1.13.9 before both.
        assert_eq!(names, ["1.13.9", "1.14.2", "1.15.0-alpha.1"]);
    }

    #[test]
    fn a_version_with_no_record_is_reported_rather_than_left_out() {
        let (_root, dirs) = dirs();
        install_one(&dirs, "v1.14.2");
        create_dir(&dirs.versions().join("1.13.9"), "a test directory").expect("a directory");

        let refused = installed(&dirs);

        assert_eq!(
            refused,
            Err(Error::Record {
                version: "1.13.9".to_string(),
                reason: "there is no record",
            })
        );
    }

    #[test]
    fn the_current_version_is_not_removable() {
        let (_root, dirs) = dirs();
        let version = Version::from_tag("v1.14.2");
        install_one(&dirs, "v1.14.2");

        assert_eq!(
            uninstall(&dirs, &version, Some(&version)),
            Err(Error::Current {
                version: version.clone()
            })
        );
        assert!(dirs.version(&Version::from_tag("v1.14.2")).exists());

        // And the other one is.
        install_one(&dirs, "v1.13.9");
        uninstall(&dirs, &Version::from_tag("v1.13.9"), Some(&version)).expect("a removal");
        assert_eq!(installed(&dirs).expect("the installed versions").len(), 1);
    }
}
