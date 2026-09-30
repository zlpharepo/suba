//! The sing-box core: which version, where it lives, and what a release holds.
//!
//! One rule runs through this module: **the version and the bytes are recorded
//! together.** A release archive is taken from the network once, hashed, and
//! what is kept is the hash; the schema a version is judged against is generated
//! by that same binary, so "version X" and "the fields X has" can never drift
//! apart. Nothing here trusts a version number to describe a file.
//!
//! Nothing here talks to the network either: a release is *parsed* (from what an
//! API answered, which the caller fetched) and an archive is *read* (from bytes
//! the caller already has). Downloading, and running the binary, are the
//! caller's side of the same conversation — which is what keeps this testable
//! with a twenty-line fixture instead of a release.

use std::cmp::Ordering;
use std::fmt;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The largest binary this will take out of an archive (128 MiB).
///
/// The real one is about 60 MiB; past this the archive is not a sing-box
/// release, and reading it to find out is the mistake being avoided.
pub const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

/// The largest licence file this will take out of an archive (1 MiB).
///
/// The real one is ~35 KiB. It is here because the two members are read the
/// same way, and one of them is not the one worth a size limit.
pub const MAX_LICENSE_BYTES: u64 = 1024 * 1024;

/// The names the two members of a release archive are taken by.
///
/// The archive holds `<release>/sing-box` and `<release>/LICENSE`; the directory
/// is not this module's business (it carries the version), so the members are
/// matched by their file name.
const BINARY_MEMBER: &str = "sing-box";
const LICENSE_MEMBER: &str = "LICENSE";

/// Something this module refuses.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// No release asset is published with the name a platform needs.
    #[error("no asset is named {name} in this release")]
    NoAsset { name: String },
    /// The platform has no naming at all here, so there is nothing to look for.
    #[error("sing-box publishes no build for {os}-{arch} this module knows of")]
    Platform {
        os: &'static str,
        arch: &'static str,
    },
    /// A release document did not have a field this module reads.
    #[error("the release document has no {field}")]
    Release { field: &'static str },
    /// The archive could not be read as one.
    #[error("the archive could not be read: {reason}")]
    Archive { reason: &'static str },
    /// The archive holds a member this installer will not take.
    #[error("the archive member {member} is not one this installer takes")]
    Member { member: String },
    /// A member the release must have is not in it.
    #[error("the archive holds no {member}")]
    MemberMissing { member: &'static str },
    /// A member is larger than this module will read.
    #[error("the archive member {member} is larger than this installer reads")]
    MemberTooLarge { member: &'static str },
    /// The bytes are not the bytes that were recorded.
    #[error("the bytes hash to {found}, not the recorded {expected}")]
    Hash { expected: String, found: String },
    /// The version is already on this machine.
    #[error("{version} is already installed")]
    Installed { version: Version },
    /// The version is not on this machine.
    #[error("{version} is not installed")]
    NotInstalled { version: Version },
    /// The version is not one the release server publishes.
    #[error("{version} is not a version the release server publishes")]
    Unpublished { version: Version },
    /// The version is the current one, which is not removed from under it.
    #[error("{version} is the current version")]
    Current { version: Version },
    /// The version is the one running, which is not removed from under it.
    #[error("{version} is the version that is running")]
    RunningVersion { version: Version },
    /// A file this module owns could not be read or written.
    ///
    /// Where it happened is this module's own description, and the reason is the
    /// kind of failure rather than the operating system's message, which would
    /// carry a path a caller gave us.
    #[error("{at}: {reason}")]
    Files {
        at: &'static str,
        reason: &'static str,
    },
    /// A version's record does not say what a record says.
    #[error("{version}: {reason}")]
    Record {
        version: String,
        reason: &'static str,
    },
    /// The binary was asked to write its own schema and did not.
    #[error("the process did not do what it was asked: {reason}")]
    Run { reason: &'static str },
    /// The core was asked to generate something and did not.
    ///
    /// The subcommand is named, and nothing it printed is: what it prints here
    /// is a credential.
    #[error("{command}: {reason}")]
    Generate {
        command: &'static str,
        reason: &'static str,
    },
    /// A process is already running, and there is one at a time.
    #[error("a process is already running as {pid}")]
    Running { pid: u32 },
    /// A release server answered with an error status.
    #[error("the release server answered {status}: {hint}")]
    Refused { status: u16, hint: &'static str },
    /// A request did not come back.
    #[error("the request did not come back: {reason}")]
    Network { reason: &'static str },
}

/// A version sing-box publishes: the release tag without its leading `v`.
///
/// Kept as the text sing-box spelled, because that text — not a number — is what
/// a tag, a directory and an API field all agree on. Ordering is by version
/// numbers when the text parses as one, and by text when it does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version(Box<str>);

impl Version {
    /// The version a release tag names.
    pub fn from_tag(tag: &str) -> Self {
        Self(tag.trim_start_matches('v').into())
    }

    /// The version as it is spelled in a directory name or a document.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The tag it is published under.
    pub fn tag(&self) -> String {
        format!("v{}", self.0)
    }

    /// The `major.minor` it belongs to, which is the unit sing-box publishes a
    /// schema for (a patch release has none of its own).
    pub fn minor(&self) -> &str {
        let head = self.0.split('-').next().unwrap_or(&self.0);
        let mut parts = head.split('.');

        match (parts.next(), parts.next(), parts.next()) {
            (Some(major), Some(minor), _) => {
                // A borrowed slice of the two parts, found by position so no
                // allocation happens for something this short.
                let end = major.len() + 1 + minor.len();
                &self.0[..end]
            }
            _ => &self.0,
        }
    }

    /// Whether this is a pre-release: the tags sing-box spells with a suffix.
    ///
    /// Read from the tag's shape rather than from a flag, because one of the two
    /// places a release list comes from (the atom feed) has no flag.
    pub fn is_prerelease(&self) -> bool {
        self.0.contains('-')
    }

    /// The numeric parts, when the version parses as one.
    fn numbers(&self) -> Option<(u64, u64, u64, Option<&str>)> {
        let (head, prerelease) = match self.0.split_once('-') {
            Some((head, suffix)) => (head, Some(suffix)),
            None => (self.0.as_ref(), None),
        };

        let mut parts = head.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;

        if parts.next().is_some() {
            return None;
        }

        Some((major, minor, patch, prerelease))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.numbers(), other.numbers()) {
            (Some((major, minor, patch, mine)), Some((major2, minor2, patch2, theirs))) => {
                let order = (major, minor, patch).cmp(&(major2, minor2, patch2));

                if order != Ordering::Equal {
                    return order;
                }

                // A release outranks its own pre-releases; two pre-releases are
                // compared part by part, numerically where both parts are numbers
                // (so `alpha.10` outranks `alpha.9`).
                match (mine, theirs) {
                    (None, None) => Ordering::Equal,
                    (None, Some(_)) => Ordering::Greater,
                    (Some(_), None) => Ordering::Less,
                    (Some(mine), Some(theirs)) => prerelease_order(mine, theirs),
                }
            }
            _ => self.0.cmp(&other.0),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Two pre-release suffixes, part by part.
fn prerelease_order(mine: &str, theirs: &str) -> Ordering {
    let mut mine = mine.split('.');
    let mut theirs = theirs.split('.');

    loop {
        match (mine.next(), theirs.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(mine), Some(theirs)) => {
                let order = match (mine.parse::<u64>(), theirs.parse::<u64>()) {
                    (Ok(mine), Ok(theirs)) => mine.cmp(&theirs),
                    _ => mine.cmp(theirs),
                };

                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

/// One downloadable file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Its file name, which is `<binary>-<version>-<platform>.<archive>`.
    pub name: String,
    /// Where it is.
    pub url: String,
    /// How large it is, as the release says.
    pub size: u64,
    /// The sha256 the release publishes for it, when it publishes one.
    pub sha256: Option<String>,
}

/// One published release, as the release list describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The version it is.
    pub version: Version,
    /// Whether it is a pre-release (the tag says so).
    pub prerelease: bool,
    /// Whether it is a draft (nothing outside the project can see one).
    pub draft: bool,
    /// Where the assets are, when the release names the page.
    pub html_url: Option<String>,
    /// The files it published.
    pub assets: Vec<Asset>,
}

impl Release {
    /// Read one release from the document the release API answers with.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, Error> {
        let tag = value
            .get("tag_name")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Release { field: "tag_name" })?;

        let assets = match value.get("assets").and_then(serde_json::Value::as_array) {
            Some(assets) => assets
                .iter()
                .filter_map(|asset| {
                    Some(Asset {
                        name: asset.get("name")?.as_str()?.to_string(),
                        url: asset.get("browser_download_url")?.as_str()?.to_string(),
                        size: asset.get("size").and_then(serde_json::Value::as_u64)?,
                        sha256: asset
                            .get("digest")
                            .and_then(serde_json::Value::as_str)
                            .and_then(|digest| digest.strip_prefix("sha256:"))
                            .map(str::to_string),
                    })
                })
                .collect(),
            None => Vec::new(),
        };

        Ok(Self {
            version: Version::from_tag(tag),
            prerelease: value
                .get("prerelease")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or_else(|| Version::from_tag(tag).is_prerelease()),
            draft: value
                .get("draft")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            html_url: value
                .get("html_url")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            assets,
        })
    }

    /// The newest stable release in a list, which is the version to offer first.
    ///
    /// Drafts are not released and pre-releases are not what a default should
    /// be; what is left is compared as versions, not as text.
    pub fn newest_stable(releases: &[Self]) -> Option<&Self> {
        releases
            .iter()
            .filter(|release| !release.draft && !release.prerelease)
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    /// The asset this platform runs, by the name sing-box gives it.
    pub fn asset_for(&self, platform: &str) -> Result<&Asset, Error> {
        let name = format!("sing-box-{}-{platform}.tar.gz", self.version);

        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .ok_or(Error::NoAsset { name })
    }
}

/// The platform sing-box names its builds for, as `<os>-<arch>`.
///
/// The names are sing-box's, not ours: `darwin-arm64`, `linux-amd64`. A
/// platform this build has no name for is refused rather than guessed at — a
/// download of "something close" is a binary that does not run.
pub fn platform() -> Result<&'static str, Error> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "arm") => "linux-armv7",
        (os, arch) => return Err(Error::Platform { os, arch }),
    })
}

/// What a release archive held, once its two members are out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The binary.
    pub binary: Vec<u8>,
    /// The licence it is distributed under, which travels beside it.
    pub license: Vec<u8>,
}

/// Read a release archive: a gzipped tar holding a binary and a licence.
///
/// Exactly two members are taken, by file name, and anything else in the
/// archive is refused by name — an archive with a third file in it is not a
/// release this installer understands, and silently ignoring it would be
/// ignoring whatever it is. Member paths get the same treatment a file name
/// does: absolute paths, `..` and anything that is not a plain name are refused
/// rather than resolved.
pub fn extract(archive: &[u8]) -> Result<Extracted, Error> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));

    let mut binary = None;
    let mut license = None;

    let entries = tar.entries().map_err(|_| Error::Archive {
        reason: "not a gzipped tar archive",
    })?;

    for entry in entries {
        let entry = entry.map_err(|_| Error::Archive {
            reason: "a member could not be read",
        })?;

        let path = entry.path().map_err(|_| Error::Archive {
            reason: "a member has no readable name",
        })?;

        if entry.header().entry_type().is_dir() {
            continue;
        }

        let name = plain_member_name(&path)?;

        let (slot, limit) = match name {
            name if name == BINARY_MEMBER => (&mut binary, MAX_BINARY_BYTES),
            name if name == LICENSE_MEMBER => (&mut license, MAX_LICENSE_BYTES),
            other => {
                return Err(Error::Member {
                    member: other.to_string(),
                })
            }
        };

        let member = if limit == MAX_BINARY_BYTES {
            BINARY_MEMBER
        } else {
            LICENSE_MEMBER
        };

        if entry.header().size().unwrap_or_default() > limit {
            return Err(Error::MemberTooLarge { member });
        }

        let mut bytes = Vec::new();
        entry
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Archive {
                reason: "a member could not be read",
            })?;

        *slot = Some(bytes);
    }

    let binary = binary.ok_or(Error::MemberMissing {
        member: BINARY_MEMBER,
    })?;
    let license = license.ok_or(Error::MemberMissing {
        member: LICENSE_MEMBER,
    })?;

    Ok(Extracted { binary, license })
}

/// The last part of a member's path, refusing anything that is not a plain name.
fn plain_member_name(path: &Path) -> Result<&str, Error> {
    let mut name = None;

    for component in path.components() {
        match component {
            Component::Normal(part) => {
                name = part.to_str();
            }
            // A parent, a root or a prefix is a member that means to be written
            // somewhere other than where it says: refused, never resolved.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::Member {
                    member: path.to_string_lossy().into_owned(),
                })
            }
            Component::CurDir => {}
        }
    }

    name.ok_or(Error::Member {
        member: path.to_string_lossy().into_owned(),
    })
}

/// The sha256 of some bytes, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(bytes);

    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Where the sing-box module keeps everything it owns.
///
/// The layout the requirements name, in one place so that every caller agrees on
/// it: versions side by side under `versions/`, the configuration it is running
/// under `config/`, and sing-box's own working directory under `data/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    /// The module's root (`<data>/sing-box`).
    pub root: PathBuf,
}

impl Dirs {
    /// The module's directories under a data directory.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: data_dir.into().join("sing-box"),
        }
    }

    /// Where installed versions live.
    pub fn versions(&self) -> PathBuf {
        self.root.join("versions")
    }

    /// One version's directory.
    pub fn version(&self, version: &Version) -> PathBuf {
        self.versions().join(version.as_str())
    }

    /// One version's binary.
    pub fn binary(&self, version: &Version) -> PathBuf {
        self.version(version).join("bin").join("sing-box")
    }

    /// One version's licence.
    pub fn license(&self, version: &Version) -> PathBuf {
        self.version(version).join("bin").join("LICENSE")
    }

    /// One version's schema, which that version's own binary generated.
    pub fn schema(&self, version: &Version) -> PathBuf {
        self.version(version).join("schema.json")
    }

    /// One version's record.
    pub fn metadata(&self, version: &Version) -> PathBuf {
        self.version(version).join("metadata.json")
    }

    /// The version currently in use.
    pub fn current(&self) -> PathBuf {
        self.root.join("current.json")
    }

    /// Where the configuration sing-box is run with is assembled.
    pub fn config(&self) -> PathBuf {
        self.root.join("config")
    }

    /// sing-box's own working directory, which its cache lives in.
    pub fn work(&self) -> PathBuf {
        self.root.join("data")
    }
}

/// What is kept about an installed version.
///
/// Facts only: which bytes, from where, when. Nothing here is derived from the
/// bytes (what protocols that version can express, whether a configuration
/// validates) — those are computed from the schema on demand, so they cannot go
/// stale behind a file that changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// The version.
    pub version: Version,
    /// The tag it was published under.
    pub tag: String,
    /// The asset it was taken from.
    pub asset: String,
    /// The platform that asset is for.
    pub platform: String,
    /// The sha256 of the archive, as this module measured it.
    pub asset_sha256: String,
    /// The sha256 of the binary, as this module measured it.
    pub binary_sha256: String,
    /// The sha256 of the schema that binary generated.
    pub schema_sha256: String,
    /// When it was installed, in seconds since the epoch.
    pub installed_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A release document, shaped the way the API answers (a locally built
    /// fixture: two assets, one of them ours, one of them not).
    const RELEASE: &str = r#"{
        "tag_name": "v1.14.2",
        "prerelease": false,
        "draft": false,
        "html_url": "https://example.invalid/releases/tag/v1.14.2",
        "assets": [
            {
                "name": "sing-box-1.14.2-darwin-arm64.tar.gz",
                "browser_download_url": "https://example.invalid/a.tar.gz",
                "size": 29161521,
                "digest": "sha256:925c5382eca8492b0150f868a6db20b18290a38700e621724b3703fd453e032d"
            },
            {
                "name": "sing-box_1.14.2_linux_amd64.deb",
                "browser_download_url": "https://example.invalid/a.deb",
                "size": 1
            }
        ]
    }"#;

    fn release() -> Release {
        let value: serde_json::Value = serde_json::from_str(RELEASE).expect("the fixture is JSON");

        Release::from_json(&value).expect("the fixture is a release")
    }

    #[test]
    fn a_version_is_the_tag_without_its_v() {
        let version = Version::from_tag("v1.14.2");

        assert_eq!(version.as_str(), "1.14.2");
        assert_eq!(version.tag(), "v1.14.2");
        assert_eq!(version.minor(), "1.14");
        assert!(!version.is_prerelease());
        assert!(Version::from_tag("v1.15.0-alpha.9").is_prerelease());
    }

    /// Versions are compared as versions, not as text: `1.9.0` is older than
    /// `1.14.2`, and a release outranks its own pre-releases.
    #[test]
    fn versions_compare_by_their_parts() {
        let older = Version::from_tag("v1.9.0");
        let newer = Version::from_tag("v1.14.2");
        let release = Version::from_tag("v1.15.0");
        let alpha9 = Version::from_tag("v1.15.0-alpha.9");
        let alpha10 = Version::from_tag("v1.15.0-alpha.10");

        assert!(older < newer);
        assert!(newer < release);
        assert!(alpha9 < release);
        assert!(alpha10 < release);
        assert!(alpha9 < alpha10, "alpha.10 is after alpha.9");
    }

    #[test]
    fn the_newest_stable_release_is_the_one_not_marked_prerelease() {
        let alpha: serde_json::Value = serde_json::from_str(
            r#"{"tag_name": "v1.16.0-alpha.1", "prerelease": true, "assets": []}"#,
        )
        .unwrap();
        let older: serde_json::Value =
            serde_json::from_str(r#"{"tag_name": "v1.13.0", "prerelease": false, "assets": []}"#)
                .unwrap();

        let releases = vec![
            Release::from_json(&alpha).unwrap(),
            release(),
            Release::from_json(&older).unwrap(),
        ];

        assert_eq!(
            Release::newest_stable(&releases).map(|release| release.version.clone()),
            Some(Version::from_tag("v1.14.2"))
        );
    }

    #[test]
    fn a_release_is_read_with_the_hash_its_assets_publish() {
        let release = release();

        assert_eq!(release.version.as_str(), "1.14.2");
        assert!(!release.prerelease);
        assert_eq!(release.assets.len(), 2);

        let asset = release.asset_for("darwin-arm64").expect("our platform");
        assert_eq!(asset.size, 29_161_521);
        assert_eq!(
            asset.sha256.as_deref(),
            Some("925c5382eca8492b0150f868a6db20b18290a38700e621724b3703fd453e032d")
        );

        // An asset the release publishes none of is refused by the name it
        // looked for, never by "not found".
        assert_eq!(
            release.asset_for("linux-riscv64"),
            Err(Error::NoAsset {
                name: "sing-box-1.14.2-linux-riscv64.tar.gz".to_string()
            })
        );
    }

    /// The platform names are sing-box's own, and this build's platform is one
    /// of them — a smoke test that the mapping here and a release agree.
    #[test]
    fn this_platform_is_named_the_way_a_release_names_it() {
        let platform = platform().expect("a platform this build has a name for");

        assert!(
            platform.starts_with("darwin-") || platform.starts_with("linux-"),
            "{platform}"
        );
    }

    #[test]
    fn the_layout_is_where_the_requirements_put_everything() {
        let dirs = Dirs::new("/data");
        let version = Version::from_tag("v1.14.2");

        assert_eq!(dirs.versions(), Path::new("/data/sing-box/versions"));
        assert_eq!(
            dirs.binary(&version),
            Path::new("/data/sing-box/versions/1.14.2/bin/sing-box")
        );
        assert_eq!(
            dirs.license(&version),
            Path::new("/data/sing-box/versions/1.14.2/bin/LICENSE")
        );
        assert_eq!(
            dirs.schema(&version),
            Path::new("/data/sing-box/versions/1.14.2/schema.json")
        );
        assert_eq!(
            dirs.metadata(&version),
            Path::new("/data/sing-box/versions/1.14.2/metadata.json")
        );
        assert_eq!(dirs.current(), Path::new("/data/sing-box/current.json"));
        assert_eq!(dirs.config(), Path::new("/data/sing-box/config"));
        assert_eq!(dirs.work(), Path::new("/data/sing-box/data"));
    }

    /// A release archive, built here so the archive format is exercised without
    /// a network or a system `tar`.
    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
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

    #[test]
    fn the_two_members_come_out_of_a_release_archive() {
        let bytes = archive(&[
            ("sing-box-1.14.2-darwin-arm64/LICENSE", b"GPL-3.0"),
            ("sing-box-1.14.2-darwin-arm64/sing-box", b"a binary"),
        ]);

        let extracted = extract(&bytes).expect("a release archive");

        assert_eq!(extracted.binary, b"a binary");
        assert_eq!(extracted.license, b"GPL-3.0");
    }

    /// Anything else in the archive is refused by name: an archive that holds a
    /// third file is not a release this installer understands.
    #[test]
    fn a_member_that_is_not_one_of_the_two_is_refused_by_name() {
        let bytes = archive(&[
            ("release/sing-box", b"a binary"),
            ("release/LICENSE", b"GPL-3.0"),
            ("release/README.md", b"hello"),
        ]);

        assert_eq!(
            extract(&bytes),
            Err(Error::Member {
                member: "README.md".to_string()
            })
        );
    }

    /// A member that means to be written somewhere else is refused, not
    /// resolved, and so is one that is not there at all.
    #[test]
    fn a_member_outside_the_archive_is_refused() {
        // Written by hand: the `tar` writer refuses to make this header, which
        // is exactly why the reader has to.
        let mut header = tar::Header::new_gnu();
        let name = b"release/../../etc/sing-box";
        header.as_gnu_mut().expect("a GNU header").name[..name.len()].copy_from_slice(name);
        header.set_size(9);
        header.set_mode(0o644);
        header.set_cksum();

        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        builder
            .append(&header, std::io::Cursor::new(b"a binary\n"))
            .expect("the hostile member");
        let bytes = builder
            .into_inner()
            .expect("the encoder")
            .finish()
            .expect("gzip");

        assert_eq!(
            extract(&bytes),
            Err(Error::Member {
                member: "release/../../etc/sing-box".to_string()
            })
        );

        let incomplete = archive(&[("release/sing-box", b"a binary")]);

        assert_eq!(
            extract(&incomplete),
            Err(Error::MemberMissing {
                member: LICENSE_MEMBER
            })
        );
    }

    #[test]
    fn bytes_that_are_not_an_archive_are_refused() {
        assert!(matches!(
            extract(b"not an archive"),
            Err(Error::Archive { .. })
        ));
    }

    #[test]
    fn a_record_says_which_bytes_and_nothing_else() {
        let metadata = Metadata {
            version: Version::from_tag("v1.14.2"),
            tag: "v1.14.2".to_string(),
            asset: "sing-box-1.14.2-darwin-arm64.tar.gz".to_string(),
            platform: "darwin-arm64".to_string(),
            asset_sha256: sha256_hex(b"archive"),
            binary_sha256: sha256_hex(b"binary"),
            schema_sha256: sha256_hex(b"schema"),
            installed_at: 1_700_000_000,
        };

        let text = serde_json::to_string(&metadata).expect("a record");
        let read_back: Metadata = serde_json::from_str(&text).expect("the record again");

        assert_eq!(read_back, metadata);
        assert!(text.contains("\"installed_at\":1700000000"), "{text}");
    }
}
