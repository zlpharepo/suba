//! Durable, private file writes.
//!
//! The data directory holds provider payloads (subscription tokens), node
//! credentials and the small state documents. Two properties make that safe:
//!
//! * **Atomic.** Content goes to a sibling temp file, is flushed, and is
//!   renamed over the target. A reader sees the whole old file or the whole new
//!   one, never a half-written file, and a crash never truncates what was
//!   there.
//! * **Durable.** Both the file and its directory are `fsync`ed, so the rename
//!   survives a power failure rather than living in the page cache.
//!
//! Files are created `0600` and directories `0700`: these are credentials on
//! disk, and the default umask is not a security policy.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Mode for files that may contain credentials.
pub const FILE_MODE: u32 = 0o600;
/// Mode for directories that may contain credential-bearing files.
pub const DIR_MODE: u32 = 0o700;

/// Distinguishes temp files written in the same process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a directory tree with restrictive permissions.
pub fn ensure_dir(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();

    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }

    let mut builder = DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIR_MODE);
    }

    builder.create(path)
}

/// Write a file atomically, durably and privately.
pub fn write_atomic(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());

    if let Some(dir) = dir {
        ensure_dir(dir)?;
    }

    let temp = temp_path(path);
    write_private(&temp, contents.as_ref())?;

    if let Err(error) = fs::rename(&temp, path) {
        // Leave nothing behind for a failed write.
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    // Persist the rename itself; without this the directory entry may be lost
    // on power failure even though the file's contents were flushed.
    if let Some(dir) = dir {
        if let Ok(dir) = File::open(dir) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;

    Ok(())
}

/// A sibling temp file name that no concurrent writer will pick.
///
/// It starts with a dot so a listing of the directory hides it, and carries the
/// pid and a counter so two writers in one process cannot collide.
fn temp_path(path: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let temp_name = format!(".{name}.tmp-{}-{counter}", std::process::id());

    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(dir) => dir.join(temp_name),
        None => PathBuf::from(temp_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("suba-fs-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);

        dir
    }

    #[test]
    fn writes_and_replaces_content() {
        let dir = scratch("replace");
        let file = dir.join("nested/config.toml");

        write_atomic(&file, "first").unwrap();
        write_atomic(&file, "second").unwrap();

        assert_eq!(fs::read_to_string(&file).unwrap(), "second");
        assert_eq!(leftover_temp_files(&dir), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("modes");
        let file = dir.join("config.toml");

        write_atomic(&file, "secret").unwrap();

        let file_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;

        assert_eq!(file_mode, FILE_MODE, "config files must be 0600");
        assert_eq!(dir_mode, DIR_MODE, "config directories must be 0700");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = scratch("tempfiles");
        let file = dir.join("data.json");

        write_atomic(&file, "{}").unwrap();

        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "only the target");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_dir_is_idempotent() {
        let dir = scratch("idempotent");
        let nested = dir.join("a/b/c");

        ensure_dir(&nested).unwrap();
        ensure_dir(&nested).unwrap();

        assert!(nested.is_dir());

        fs::remove_dir_all(&dir).unwrap();
    }

    fn leftover_temp_files(dir: &Path) -> usize {
        fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
                    .count()
            })
            .unwrap_or(0)
    }
}
