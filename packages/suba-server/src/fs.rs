//! Durable, private file access inside a directory this program owns.
//!
//! The data directory holds provider payloads (subscription tokens), node
//! credentials and the small state documents, and the configuration directory
//! holds the administrator's password hash and the signing key. Four properties
//! keep what is written there private, whole, and where it was meant to go:
//!
//! * **Trusted.** A directory is opened, checked to be owned by the user running
//!   this process and not writable by anyone else, and tightened to `0700`.
//!   A directory someone else can write to is refused rather than fixed: that is
//!   the case where another user can plant files, and repairing the mode would
//!   hide it.
//! * **Relative.** Every operation goes through a descriptor for the directory,
//!   so the path that led to it cannot be swapped underneath the operation and
//!   redirect it somewhere else.
//! * **Named, not pathed.** A file is addressed by a name that may not contain a
//!   separator or be `.`/`..`. A provider name from a request arrives here, and
//!   this is the last point before it would become a path out of the directory.
//! * **Atomic and durable.** A write goes to a sibling temp file created
//!   `O_EXCL`, is flushed, is renamed over the target, and the directory is
//!   `fsync`ed — so a reader sees the whole old file or the whole new one, and
//!   the rename survives a crash.
//!
//! Two deliberate limits, so nobody reads more into this than it does:
//!
//! * A **directory** that is a symlink is followed. The operator configured that
//!   path, and refusing it would break a data directory linked to another disk.
//!   What is never followed is a *file* symlink inside it: a planted
//!   `sessions.toml -> /etc/shadow` is refused rather than read, and a planted
//!   FIFO is refused rather than blocking the process forever.
//! * The directory is checked on **every** operation rather than held open for
//!   the life of the process. Writing a file opens it once and does everything
//!   relative to that descriptor, which is where the check-then-use gap would
//!   otherwise be; a swap between two writes is caught by the next check.

use std::{
    fs::{DirBuilder, File, Permissions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use rustix::{
    fs::{chown, open, openat, renameat, unlinkat, AtFlags, Gid, Mode, OFlags, Uid},
    io::Errno,
    process::geteuid,
};

/// Mode for files that may contain credentials.
pub const FILE_MODE: u32 = 0o600;
/// Mode for directories that may contain credential-bearing files.
pub const DIR_MODE: u32 = 0o700;
/// The permission bits that mean "somebody other than the owner may write".
const OTHER_WRITE: u32 = 0o022;
/// The longest name this will create or open.
const MAX_NAME: usize = 255;

/// Distinguishes temp files written in the same process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The user files are written for, when this process is not that user.
static FOR: OnceLock<Option<(u32, u32)>> = OnceLock::new();

/// Write files for this user from now on.
///
/// A root run exists to start a core, not to take the operator's files away from
/// them: without this, an instance started as root leaves a `config.json` its
/// owner cannot read, let alone edit, and the only way back is a `chown -R`.
/// Taken once, before any store is built.
pub fn write_for(uid: u32, gid: u32) {
    let _ = FOR.set(Some((uid, gid)));
}

/// Give a file or directory just created back to the user this process writes
/// for.
///
/// Best effort by design: the thing asked for has already happened, and an owner
/// that could not be changed is a file the operator notices by not being able to
/// edit it — not a reason to fail a save that landed.
fn settle_with(path: &Path) {
    let Some((uid, gid)) = FOR.get().copied().flatten() else {
        return;
    };

    let _ = chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
}

/// Create a directory tree with restrictive permissions.
pub fn ensure_dir(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();

    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }

    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(DIR_MODE);
    builder.create(path)?;
    settle_with(path);

    Ok(())
}

/// Write `name` inside `dir`, replacing whatever is there.
///
/// `dir` is created when it is missing. The write is atomic, durable and private:
/// see the module documentation for what each of those means.
pub fn write_atomic(dir: &Path, name: &str, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let name = plain_name(dir, name)?;
    let directory = open_private(dir, true)?;
    let temp = temp_name(name);

    let opened = openat(
        &directory,
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        // `Mode`'s bits are `mode_t`, which is narrower than a `u32` everywhere
        // this runs; nothing above `0o777` is ever passed.
        Mode::from_bits_truncate(FILE_MODE as u16),
    );

    let mut file = match opened {
        Ok(fd) => File::from(fd),
        Err(error) => return Err(io_error(error)),
    };

    // Flushed before the rename: a rename that lands before the data reaches the
    // disk is a file whose name is right and whose contents are not.
    let written = file
        .write_all(contents.as_ref())
        .and_then(|()| file.sync_all());
    drop(file);

    if let Err(error) = written {
        let _ = unlinkat(&directory, temp.as_str(), AtFlags::empty());
        return Err(error);
    }

    if let Err(error) = renameat(&directory, temp.as_str(), &directory, name) {
        // Leave nothing behind for a failed write.
        let _ = unlinkat(&directory, temp.as_str(), AtFlags::empty());
        return Err(io_error(error));
    }

    // Persist the rename itself; without this the directory entry may be lost on
    // power failure even though the file's contents were flushed. Best effort: a
    // filesystem that will not sync a directory is not a reason to fail a write
    // that already landed.
    let _ = rustix::fs::fsync(&directory);

    settle_with(&dir.join(name));

    Ok(())
}

/// Read `name` inside `dir`, or `None` when it is not there.
///
/// A missing directory reads as `None` as well: nothing has been written yet,
/// which is the answer the caller wants rather than an error to handle. A file
/// that is not a regular file, or that is a symlink, is refused.
pub fn read_to_string(dir: &Path, name: &str) -> io::Result<Option<String>> {
    let name = plain_name(dir, name)?;

    let directory = match open_private(dir, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };

    let opened = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );

    let mut file = match opened {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        // `NOFOLLOW` refusing the final component. Reported as a refusal with a
        // reason rather than left as the raw loop error, because "this file is a
        // link, and following it is not something this program does" is the
        // thing the operator needs to read.
        Err(Errno::LOOP) => return Err(refused(dir, name, "is a symbolic link")),
        Err(error) => return Err(io_error(error)),
    };

    // A symlink is already refused by `NOFOLLOW`; this also refuses a FIFO, a
    // device or a directory planted under a name we read, one of which would
    // otherwise block forever instead of failing.
    if !file.metadata()?.is_file() {
        return Err(refused(dir, name, "is not a regular file"));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    Ok(Some(contents))
}

/// The names of the regular files directly inside `dir`, sorted; a directory
/// that is not there is empty, because nothing has been written yet.
///
/// The directory is put through the same trust check as every other operation.
/// What comes back is a **name**, never a path, and it is one a caller hands
/// straight back to `read_to_string`/`write_atomic`, which refuse anything that
/// is not a plain name — so a hostile entry cannot become a path out of `dir`.
pub fn list(dir: &Path) -> io::Result<Vec<String>> {
    if let Err(error) = open_private(dir, false) {
        return match error.kind() {
            io::ErrorKind::NotFound => Ok(Vec::new()),
            _ => Err(error),
        };
    }

    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    names.sort();

    Ok(names)
}

/// Forget `name` inside `dir`.
///
/// Removing what is not there is not a failure: the caller is getting rid of
/// something, and an absent file is already gone.
pub fn remove(dir: &Path, name: &str) -> io::Result<()> {
    let name = plain_name(dir, name)?;

    let directory = match open_private(dir, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    match unlinkat(&directory, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

/// Open `path` as a directory this program may keep files in.
///
/// Created first when `create`, then checked — never the other way round: a
/// check on a directory that is about to be replaced says nothing about the one
/// the next operation will use.
fn open_private(path: &Path, create: bool) -> io::Result<File> {
    if create {
        ensure_dir(path)?;
    }

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;

    let directory = File::from(fd);
    let metadata = directory.metadata()?;
    let mode = metadata.mode() & 0o777;

    if let Err(reason) = trust(metadata.uid(), mode, geteuid().as_raw()) {
        return Err(refused(path, "", reason));
    }

    // Ours and private from others, but perhaps readable by them. Tighter is the
    // point of this directory, and the mode is not the operator's to loosen.
    if mode != DIR_MODE {
        directory.set_permissions(Permissions::from_mode(DIR_MODE))?;
    }

    Ok(directory)
}

/// Whether a directory is one this process may keep files in.
///
/// Root is answered on its own, because it can reach any directory there is: who
/// owns one says nothing about what root may do, and comparing against root's
/// own id was what stopped a root run from using the operator's data directory.
fn trust(owner: u32, mode: u32, euid: u32) -> Result<(), &'static str> {
    if euid != 0 && owner != euid {
        return Err("is not owned by the user running suba");
    }
    if mode & OTHER_WRITE != 0 {
        return Err("is writable by a user other than its owner");
    }

    Ok(())
}

/// Give a directory tree back to the user it belongs to.
///
/// A run that started as root writes what root owns, and an operator who then
/// runs without a privilege would find their own instance unreadable. Only what
/// root owns is changed — a file that already belongs to somebody else is left
/// alone — and symlinks are not followed, so nothing outside the tree is
/// reached.
pub fn hand_back(dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
    // The root of a filesystem is not a data directory, and handing it to a user
    // is not something a mistyped `--data /` should be able to do.
    if dir.as_os_str().is_empty() || dir.parent().is_none() {
        return Err(refused(dir, "", "is not a directory to hand back"));
    }

    let owner = Some(Uid::from_raw(uid));
    let group = Some(Gid::from_raw(gid));

    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.uid() == 0 => chown(dir, owner, group)?,
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = entry?;
        // `DirEntry::metadata` is the entry itself, not what a link points at.
        let metadata = entry.metadata()?;
        let path = entry.path();

        if metadata.uid() == 0 {
            chown(&path, owner, group)?;
        }
        if metadata.is_dir() {
            hand_back(&path, uid, gid)?;
        }
    }

    Ok(())
}

/// A name that may be a file inside `dir`.
///
/// Rejecting a path-shaped name here is what keeps a provider name from a
/// request a file name instead of a way out of the directory.
fn plain_name<'a>(dir: &Path, name: &'a str) -> io::Result<&'a str> {
    let plain = !name.is_empty()
        && name.len() <= MAX_NAME
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0']);

    match plain {
        true => Ok(name),
        false => Err(refused(dir, name, "is not a file name")),
    }
}

/// A sibling temp file name that no concurrent writer will pick.
///
/// It starts with a dot so a listing of the directory hides it, and carries the
/// pid and a counter so two writers in one process cannot collide. A name this
/// module generated cannot be a symlink either: it is created `O_EXCL`.
fn temp_name(name: &str) -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    format!(".{name}.tmp-{}-{counter}", std::process::id())
}

/// A refusal, naming the file it is about.
///
/// The path and the file name are the operator's own configuration, not a
/// credential, and a refusal that does not say which file is a puzzle.
fn refused(dir: &Path, name: &str, reason: &str) -> io::Error {
    let what = match name.is_empty() {
        true => dir.display().to_string(),
        false => dir.join(name).display().to_string(),
    };

    io::Error::new(io::ErrorKind::PermissionDenied, format!("{what} {reason}"))
}

/// The `std` shape of a `rustix` failure, so this module speaks one error type.
fn io_error(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, path::PathBuf};

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("suba-fs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        dir
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Root is answered on its own, and a directory somebody else can write to
    /// is never trusted — which is the one thing that check is for.
    #[test]
    fn a_directory_is_trusted_by_who_may_write_it() {
        assert!(trust(501, 0o700, 501).is_ok(), "its own owner");
        assert!(trust(0, 0o700, 0).is_ok(), "root, owning it");
        assert!(
            trust(501, 0o700, 0).is_ok(),
            "root, on a directory that is somebody else's: it can reach \
             anything there is, so the owner says nothing about what it may do"
        );

        assert!(trust(501, 0o700, 502).is_err(), "another user's directory");
        assert!(trust(501, 0o755, 501).is_ok(), "readable by others is fine");
        assert!(trust(501, 0o777, 501).is_err(), "writable by others");
        assert!(trust(501, 0o777, 0).is_err(), "writable by others, as root");
    }

    /// The root of a filesystem is not a data directory, and a mistyped
    /// `--data /` must not be able to hand it to a user.
    #[test]
    fn handing_back_refuses_a_path_that_is_not_a_data_directory() {
        assert!(hand_back(Path::new("/"), 501, 20).is_err());
        assert!(hand_back(Path::new(""), 501, 20).is_err());
    }

    /// An owner that cannot be applied is not a reason to lose a write: the
    /// thing asked for has already happened, and a file the operator cannot edit
    /// is something they notice, not a failure to report here.
    #[test]
    fn a_write_lands_even_when_its_owner_cannot_be_changed() {
        let dir = scratch("settle-with");
        fs::create_dir_all(&dir).unwrap();

        // A user this test is almost never, so the change is refused wherever it
        // can be. Taken once per process, which is how the server takes it.
        write_for(1, 1);

        assert!(write_atomic(&dir, "held", b"x").is_ok());
        assert_eq!(fs::read(dir.join("held")).unwrap(), b"x");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn handing_back_a_directory_that_is_not_there_is_not_a_failure() {
        let dir = scratch("hand-back-absent");

        assert!(hand_back(&dir, 501, 20).is_ok());
    }

    /// Only what root owns is changed: a file that already belongs to somebody
    /// else is left alone, which is what makes this safe to run at every start.
    #[test]
    fn handing_back_leaves_what_root_does_not_own_alone() {
        let dir = scratch("hand-back-other");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("theirs"), b"x").unwrap();
        let before = fs::metadata(dir.join("theirs")).unwrap().uid();

        hand_back(&dir, 501, 20).unwrap();

        assert_eq!(fs::metadata(dir.join("theirs")).unwrap().uid(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_and_replaces_content() {
        let dir = scratch("replace");

        write_atomic(&dir, "config.toml", "first").unwrap();
        write_atomic(&dir, "config.toml", "second").unwrap();

        assert_eq!(
            read_to_string(&dir, "config.toml").unwrap().as_deref(),
            Some("second")
        );
        assert_eq!(leftover_temp_files(&dir), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn file_and_directory_are_private() {
        let dir = scratch("modes");

        write_atomic(&dir, "config.toml", "secret").unwrap();

        assert_eq!(mode_of(&dir.join("config.toml")), FILE_MODE);
        assert_eq!(mode_of(&dir), DIR_MODE);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = scratch("tempfiles");

        write_atomic(&dir, "data.json", "{}").unwrap();

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

    #[test]
    fn reading_what_was_never_written_is_not_a_failure() {
        let dir = scratch("absent");

        assert_eq!(read_to_string(&dir, "nothing.toml").unwrap(), None);

        // The directory itself is absent too: still nothing to read, not an
        // error to handle.
        write_atomic(&dir, "present.toml", "x").unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(read_to_string(&dir, "present.toml").unwrap(), None);
    }

    #[test]
    fn forgetting_what_was_never_written_is_not_a_failure() {
        let dir = scratch("remove-absent");

        remove(&dir, "nothing.toml").unwrap();

        write_atomic(&dir, "present.toml", "x").unwrap();
        remove(&dir, "present.toml").unwrap();
        remove(&dir, "present.toml").unwrap();
        assert_eq!(read_to_string(&dir, "present.toml").unwrap(), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    /// A name from a request is a name, and never a way out of the directory.
    ///
    /// Every operation goes through this check, which is why the check lives
    /// here rather than at each caller: the provider name that reaches a cache
    /// file comes from a URL path segment, and `%2F` decodes to a separator.
    #[test]
    fn a_name_that_is_a_path_is_refused() {
        let dir = scratch("traversal");

        for name in [
            "../escape",
            "a/b",
            "..",
            ".",
            "",
            "back\\slash",
            "nul\0byte",
        ] {
            assert!(
                write_atomic(&dir, name, "x").is_err(),
                "write_atomic accepted {name:?}"
            );
            assert!(
                read_to_string(&dir, name).is_err(),
                "read_to_string accepted {name:?}"
            );
            assert!(remove(&dir, name).is_err(), "remove accepted {name:?}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// A symlink planted under a name we read is refused, not followed.
    ///
    /// This is the whole point of the check: a file called `sessions.toml` that
    /// points at `/etc/shadow` would otherwise be read as if it were ours.
    #[test]
    fn a_planted_symlink_is_not_followed() {
        let dir = scratch("symlink");
        let outsider = scratch("symlink-outside");

        write_atomic(&outsider, "real.toml", "not yours").unwrap();
        write_atomic(&dir, "sessions.toml", "ours").unwrap();

        fs::remove_file(dir.join("sessions.toml")).unwrap();
        symlink(outsider.join("real.toml"), dir.join("sessions.toml")).unwrap();

        let error = read_to_string(&dir, "sessions.toml").expect_err("a symlink is refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("symbolic link"), "{error}");

        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&outsider).unwrap();
    }

    /// A write replaces a planted symlink rather than writing through it.
    ///
    /// The temp file is created `O_EXCL` and the target is replaced by rename, so
    /// following a symlink is not a step a write has.
    #[test]
    fn a_write_replaces_a_planted_symlink() {
        let dir = scratch("symlink-write");
        let outsider = scratch("symlink-write-outside");

        write_atomic(&outsider, "real.toml", "untouched").unwrap();
        ensure_dir(&dir).unwrap();
        symlink(outsider.join("real.toml"), dir.join("config.toml")).unwrap();

        write_atomic(&dir, "config.toml", "ours").unwrap();

        assert_eq!(
            fs::read_to_string(outsider.join("real.toml")).unwrap(),
            "untouched",
            "the file the symlink pointed at is not what was written"
        );
        assert_eq!(
            read_to_string(&dir, "config.toml").unwrap().as_deref(),
            Some("ours")
        );

        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&outsider).unwrap();
    }

    /// A name that is not a regular file is refused rather than opened.
    ///
    /// A directory or a FIFO planted under a name we read is refused: one would
    /// be read as if it were a document, the other would block forever instead
    /// of failing.
    #[test]
    fn something_that_is_not_a_regular_file_is_not_read() {
        let dir = scratch("not-a-file");
        ensure_dir(dir.join("sessions.toml")).unwrap();

        let error = read_to_string(&dir, "sessions.toml").expect_err("a directory is refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("regular file"), "{error}");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// A directory somebody else can write to is refused, not repaired.
    ///
    /// Repairing it would hide the fact that another user could have planted
    /// what is in there, which is the thing the caller needs to know.
    #[test]
    fn a_directory_writable_by_others_is_refused() {
        let dir = scratch("world-writable");
        ensure_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o777)).unwrap();

        let error = write_atomic(&dir, "config.toml", "x").expect_err("refused");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("writable"), "{error}");
        assert!(!dir.join("config.toml").exists(), "nothing was written");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// A directory that is ours but readable by others is tightened.
    #[test]
    fn a_directory_readable_by_others_is_tightened() {
        let dir = scratch("loose-mode");
        ensure_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();

        write_atomic(&dir, "config.toml", "x").unwrap();

        assert_eq!(mode_of(&dir), DIR_MODE);

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
