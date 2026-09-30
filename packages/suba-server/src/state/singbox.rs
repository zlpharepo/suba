//! The sing-box module as the server uses it: the fragments an operator wrote,
//! the configuration assembled from them, and the process running it.
//!
//! Everything here is synchronous — each step is file I/O or a process — and the
//! handlers reach it from the blocking pool, the way observations are read. The
//! one thing held between calls is the process itself, which outlives any single
//! request.
//!
//! **The order a start keeps.** The fragments are read, assembled, checked
//! against the schema of the version that will run them, written out, and only
//! then is a process started. A configuration that does not hold up is refused
//! with the field it is about, and a core that is already serving is never
//! touched by one — which is what makes "restart" safe to offer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use suba_singbox::assemble::{self, Assembled};
use suba_singbox::core::{Dirs, Metadata, Version};
use suba_singbox::run::{self, Runner, Status};
use suba_singbox::schema::{Schema, Verdict};

use crate::{error::Error, fs};

/// The directory the operator's fragments live in, under the config directory.
const FRAGMENTS: &str = "sing-box";

/// What a fragment's file name ends in.
const EXTENSION: &str = "json";

/// The assembled configuration, named as the core is pointed at it.
pub(crate) const CONFIG: &str = "config.json";

/// The sing-box module.
pub(crate) struct SingboxStore {
    /// `<config>/sing-box`: one file per section, which this server writes but
    /// never rewrites on its own.
    fragment_dir: PathBuf,
    /// The module's own directories under the data directory.
    dirs: Dirs,
    /// The process, which outlives any request that touched it.
    runner: Arc<Runner>,
    /// The last schema read, with the hash it was read at.
    ///
    /// A schema is addressed by its bytes (I3), so holding one costs nothing but
    /// memory and saves parsing 445 KB on every form save and every start.
    schemas: Mutex<Option<(String, Arc<Schema>)>>,
}

impl SingboxStore {
    pub(crate) fn new(config_dir: &Path, data_dir: &Path) -> Self {
        Self {
            fragment_dir: config_dir.join(FRAGMENTS),
            dirs: Dirs::new(data_dir),
            runner: Arc::new(Runner::new()),
            schemas: Mutex::new(None),
        }
    }

    /// The fragments the operator wrote, one per section.
    ///
    /// A name that is not a section is refused rather than politely skipped: a
    /// file put here to matter, which silently does not, is the failure mode
    /// this whole module is written against. A name starting with a dot is this
    /// server's own half-written file and is not the operator's business.
    pub(crate) fn fragments(&self) -> Result<BTreeMap<String, Vec<u8>>, Error> {
        let listing = match std::fs::read_dir(&self.fragment_dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => {
                return Err(Error::Io(error));
            }
        };

        let mut fragments = BTreeMap::new();
        for entry in listing {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }

            let Some(section) = name.strip_suffix(&format!(".{EXTENSION}")) else {
                return Err(Error::Fragment {
                    name,
                    reason: "a fragment is one section, named <section>.json",
                });
            };

            let Some(text) = fs::read_to_string(&self.fragment_dir, &name)? else {
                continue;
            };

            fragments.insert(section.to_string(), text.into_bytes());
        }

        Ok(fragments)
    }

    /// One section's fragment, as it is on disk.
    pub(crate) fn fragment(&self, section: &str) -> Result<Option<Value>, Error> {
        let name = fragment_name(section)?;

        match fs::read_to_string(&self.fragment_dir, &name)? {
            Some(text) => Ok(Some(serde_json::from_str(&text)?)),
            None => Ok(None),
        }
    }

    /// Write one section's fragment, once the schema has taken it.
    ///
    /// The document is checked as if it were the whole configuration with this
    /// one section in it, which is what it would be: an unknown section, a wrong
    /// type or a field this version does not have is refused here, with the
    /// field path, instead of becoming a core that will not start.
    pub(crate) fn write_fragment(&self, section: &str, value: &Value) -> Result<Verdict, Error> {
        let (schema, _) = self.schema()?;

        // As if it were the whole configuration with this one section in it,
        // which is what it would be.
        let mut document = serde_json::Map::new();
        document.insert(section.to_string(), value.clone());
        let document = Value::Object(document);

        match schema.validate(&document) {
            Verdict::Failed(fault) => {
                Err(Error::Document(format!("{}: {}", fault.path, fault.reason)))
            }
            verdict => {
                let name = fragment_name(section)?;
                fs::ensure_dir(&self.fragment_dir)?;
                let body = serde_json::to_vec_pretty(value)?;
                fs::write_atomic(&self.fragment_dir, &name, body)?;

                Ok(verdict)
            }
        }
    }

    /// The version in use, when there is one.
    pub(crate) fn current(&self) -> Result<Option<Version>, Error> {
        Ok(suba_singbox::install::current(&self.dirs)?)
    }

    /// The schema of the version in use, with the bytes it was read from.
    ///
    /// The bytes are checked against the version's own record first: a schema
    /// that changed behind the record is exactly what the record is for, and a
    /// version whose schema does not match it is not one this instance will
    /// write documents against.
    pub(crate) fn schema(&self) -> Result<(Arc<Schema>, Vec<u8>), Error> {
        let version = self.current()?.ok_or(Error::NoVersion)?;

        let bytes = std::fs::read(self.dirs.schema(&version))?;
        let sha256 = suba_singbox::core::sha256_hex(&bytes);

        let record = self.record(&version)?;
        if record.schema_sha256 != sha256 {
            return Err(Error::Singbox(suba_singbox::core::Error::Hash {
                expected: record.schema_sha256,
                found: sha256,
            }));
        }

        let mut held = self.schemas.lock().expect("the schema");
        if let Some((hash, schema)) = held.as_ref() {
            if hash == &sha256 {
                return Ok((Arc::clone(schema), bytes));
            }
        }

        let schema = Arc::new(
            Schema::read(&bytes).map_err(|unreadable| Error::Schema(unreadable.to_string()))?,
        );
        *held = Some((sha256, Arc::clone(&schema)));

        Ok((schema, bytes))
    }

    /// The configuration the core would run: the fragments, and whatever a
    /// collection contributed.
    pub(crate) fn assemble(&self, generated: &[Value]) -> Result<Assembled, Error> {
        assemble::assemble(&self.fragments()?, generated)
            .map_err(|unfit| Error::Document(unfit.to_string()))
    }

    /// Write the assembled configuration where the core is pointed at it.
    pub(crate) fn write_product(&self, config: &Value) -> Result<(), Error> {
        fs::ensure_dir(self.dirs.config())?;
        let body = serde_json::to_vec_pretty(config)?;

        Ok(fs::write_atomic(&self.dirs.config(), CONFIG, body)?)
    }

    /// Whether an assembled configuration is there.
    pub(crate) fn assembled(&self) -> bool {
        self.dirs.config().join(CONFIG).is_file()
    }

    /// Whether the version in use has its binary where it should be.
    pub(crate) fn binary_in_place(&self) -> Result<bool, Error> {
        Ok(self
            .current()?
            .is_some_and(|version| self.dirs.binary(&version).is_file()))
    }

    /// Assemble the configuration, check it, write it, and run it.
    ///
    /// `generated` is the outbound half a collection contributes; a build
    /// without one passes nothing. Nothing is started until the document has
    /// been assembled, checked and written.
    pub(crate) fn start(&self, generated: &[Value]) -> Result<u32, Error> {
        let version = self.current()?.ok_or(Error::NoVersion)?;

        let assembled = self.assemble(generated)?;
        let (schema, _) = self.schema()?;
        if let Verdict::Failed(fault) = schema.validate(&assembled.config) {
            return Err(Error::Document(format!("{}: {}", fault.path, fault.reason)));
        }

        // The core's own working directory, which its cache lives in.
        fs::ensure_dir(self.dirs.work())?;
        self.write_product(&assembled.config)?;

        let binary = self.dirs.binary(&version);
        let config = self.dirs.config().join(CONFIG);
        let work = self.dirs.work();

        Ok(self.runner.spawn(run::command(&binary, &config, &work))?)
    }

    /// Ask the core to stop.
    pub(crate) fn stop(&self, patience: std::time::Duration) -> Result<(), Error> {
        Ok(self.runner.stop(patience)?)
    }

    /// What the process is doing.
    pub(crate) fn status(&self) -> Status {
        self.runner.status()
    }

    /// The last `tail` lines the core printed.
    pub(crate) fn log(&self, tail: usize) -> Vec<String> {
        self.runner.log(tail)
    }

    /// A version's record, as it was written when it was installed.
    fn record(&self, version: &Version) -> Result<Metadata, Error> {
        suba_singbox::install::installed(&self.dirs)?
            .into_iter()
            .find(|metadata| &metadata.version == version)
            .ok_or_else(|| {
                Error::Singbox(suba_singbox::core::Error::NotInstalled {
                    version: version.clone(),
                })
            })
    }
}

/// The file name a section's fragment has, refusing a name that is not one.
fn fragment_name(section: &str) -> Result<String, Error> {
    let usable = !section.is_empty()
        && !section.contains(['/', '\\', '\0'])
        && section != "."
        && section != "..";

    if !usable {
        return Err(Error::Fragment {
            name: section.to_string(),
            reason: "a section is named by a plain word",
        });
    }

    Ok(format!("{section}.{EXTENSION}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A fake release archive: a binary that writes a schema when asked and runs
    /// until it is asked to stop, and a minimal schema that accepts one section.
    fn archive() -> Vec<u8> {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "log": { "type": "object", "properties": { "level": { "type": "string" } } }
            },
            "additionalProperties": false,
            "$defs": {
                "Inbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "socks" } } }
                ] },
                "Outbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "direct" } } }
                ] }
            }
        });

        let binary = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = schema ]; then\n\
             \tprintf '%s' '{}' > \"$3\"\n\
             \texit 0\n\
             fi\n\
             echo started\n\
             trap 'exit 0' TERM\n\
             while :; do sleep 1; done\n",
            schema
        );

        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (name, bytes) in [
            ("release/sing-box", binary.as_bytes()),
            ("release/LICENSE", b"a licence"),
        ] {
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

    /// A store over a scratch directory, with one version installed and current.
    fn store() -> (Scratch, SingboxStore) {
        let scratch = Scratch::new();
        let store = SingboxStore::new(&scratch.0.join("config"), &scratch.0.join("data"));

        let version = Version::from_tag("v1.14.2");
        suba_singbox::install::install(
            &store.dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("an install");
        suba_singbox::install::set_current(&store.dirs, &version).expect("a current version");

        (scratch, store)
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static COUNTER: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "suba-server-singbox-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("a temporary directory");

            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_fragment_that_is_not_a_section_is_refused() {
        let (_scratch, store) = store();
        std::fs::create_dir_all(&store.fragment_dir).expect("the fragments directory");
        std::fs::write(store.fragment_dir.join("notes.txt"), "hello").expect("a file");

        assert!(matches!(
            store.fragments(),
            Err(Error::Fragment { name, reason })
                if name == "notes.txt" && reason == "a fragment is one section, named <section>.json"
        ));
    }

    #[test]
    fn a_fragment_is_checked_before_it_is_written() {
        let (_scratch, store) = store();

        let refused = store.write_fragment("bogus", &serde_json::json!({}));

        assert!(
            matches!(
                &refused,
                Err(Error::Document(message))
                    if message == "bogus: is not one of the fields this place takes"
            ),
            "{refused:?}"
        );
        assert!(!store.fragment_dir.join("bogus.json").exists());

        let verdict = store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");
        assert_eq!(verdict, Verdict::Ok);

        assert_eq!(
            store.fragment("log").expect("a fragment"),
            Some(serde_json::json!({ "level": "info" }))
        );
    }

    #[test]
    fn the_assembled_configuration_lands_where_the_core_is_pointed() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "warn" }))
            .expect("a fragment");

        let generated = vec![serde_json::json!({ "type": "direct", "tag": "node 1" })];
        let assembled = store.assemble(&generated).expect("an assembly");
        store.write_product(&assembled.config).expect("a product");

        assert!(store.assembled());

        let written: Value = serde_json::from_slice(
            &std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration"),
        )
        .expect("a readable configuration");

        assert_eq!(written["log"], serde_json::json!({ "level": "warn" }));
        assert_eq!(written["outbounds"][0]["tag"], "node 1");
    }

    #[test]
    fn starting_without_a_version_is_refused() {
        let scratch = Scratch::new();
        let store = SingboxStore::new(&scratch.0.join("config"), &scratch.0.join("data"));

        assert!(matches!(store.start(&[]), Err(Error::NoVersion)));
        assert!(!store.assembled());
    }

    #[test]
    fn a_broken_fragment_stops_a_start_and_leaves_the_product_alone() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");
        store.assemble(&[]).expect("an assembly");
        let assembled = store.assemble(&[]).expect("an assembly");
        store.write_product(&assembled.config).expect("a product");
        let before = std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration");

        // A fragment the schema refuses, written by hand: the one way to get one
        // past `write_fragment`, and what a start has to survive.
        std::fs::write(store.fragment_dir.join("log.json"), r#"{"level": 7}"#)
            .expect("a broken fragment");

        let refused = store.start(&[]);

        assert!(matches!(refused, Err(Error::Document(_))), "{refused:?}");
        assert_eq!(
            std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration"),
            before
        );
    }

    /// Wait until the core has said something.
    ///
    /// A stop can reach a process before it has printed its first line, which is
    /// a real thing a core can see — so a test that means to look at what it said
    /// has to wait for it to say it.
    fn wait_for(store: &SingboxStore, line: &str) {
        for _ in 0..200 {
            if store.log(run::LOG_LINES).iter().any(|said| said == line) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!(
            "the core never said {line:?}: {:?}",
            store.log(run::LOG_LINES)
        );
    }

    #[test]
    fn the_core_runs_and_stops_one_at_a_time() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");

        let pid = store.start(&[]).expect("a start");
        assert!(pid > 0);
        assert!(store.status().running);
        wait_for(&store, "started");

        let refused = store.start(&[]);
        assert!(
            matches!(
                refused,
                Err(Error::Singbox(suba_singbox::core::Error::Running { .. }))
            ),
            "{refused:?}"
        );

        store.stop(Duration::from_secs(2)).expect("a stop");

        let status = store.status();
        assert!(!status.running);
        assert_eq!(status.exits.len(), 1);
        assert!(
            store
                .log(run::LOG_LINES)
                .iter()
                .any(|line| line == "started"),
            "what the core said: {:?}",
            store.log(run::LOG_LINES)
        );
    }
}
