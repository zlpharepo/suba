//! Who this process runs as, and whose files it is working on.
//!
//! A core that creates an interface needs a privilege the HTTP server has no use
//! for, so an instance that serves such a configuration is started as root on
//! purpose. That leaves one question the process cannot answer about itself:
//! **whose files are these**. `geteuid()` says what this process may do, not who
//! it is holding data for, and the environment a `sudo` run leaves behind is
//! only there if `sudo` was configured to leave it.
//!
//! So the answer comes from the first source that can give one, in this order:
//! what the command line named, a directory that already exists, then what
//! `sudo` recorded. None of it is a secret and none of it is worth forging —
//! whoever can start this as root can already do anything as root. The point is
//! to never *guess*, and to say which source was used.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::process::geteuid;

use crate::error::Error;

/// Where the user this instance works for was named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The command line: the operator said so.
    Named,
    /// The owner of the data or configuration directory: a file that already
    /// says whose it is.
    Existing,
    /// `SUDO_UID` and `SUDO_GID`, which the `sudo` that started this recorded.
    /// Whether they are there at all depends on how `sudo` is configured and
    /// how it was invoked, so this is the last source tried.
    Sudo,
}

/// What the command line said about running with a privilege.
///
/// Three answers are needed because none of them can be inferred: whether root
/// was meant, and whose files these are when it was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Privileged {
    /// Whether the command line said so at all.
    pub acknowledged: bool,
    /// The user and group it named, when it named them.
    pub user: Option<u32>,
    pub group: Option<u32>,
}

/// Who this process runs as, and whose files these are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// The effective user: what a started core inherits when the module asks
    /// for it, and what this process may do.
    pub euid: u32,
    /// The user and group this instance's files belong to, and the user a core
    /// is dropped to when the module asks for that. Absent when this process is
    /// not root, because then there is nothing to drop to.
    pub operator: Option<(u32, u32)>,
    /// Which source answered.
    pub source: Option<Source>,
}

impl Identity {
    /// Resolve this process's identity, refusing when a root run cannot be told
    /// whose files it is holding.
    ///
    /// Refusing rather than assuming is the point: a wrong answer here means a
    /// core running as the wrong user, or — worse — as root when nobody asked,
    /// so an unanswerable question is an error and not a default.
    pub fn discover(privileged: Privileged, dirs: &[&Path]) -> Result<Self, Error> {
        let euid = geteuid().as_raw();

        if euid != 0 {
            // Asked for and not given is worth saying out loud: the module's
            // switch is what decides a core's privilege, and it cannot be on
            // here — a start that wants it is refused, later and elsewhere.
            if privileged.acknowledged {
                tracing::warn!(
                    "--run-as-root was given, and this process is not root: a core that has to \
                     be root will be refused when it is started"
                );
            }

            return Ok(Self {
                euid,
                operator: None,
                source: None,
            });
        }
        // Two refusals, in the order they can be acted on: whether root was
        // meant at all, then whose files these are.
        if !privileged.acknowledged {
            return Err(Error::RootNotAcknowledged);
        }

        let named = privileged
            .user
            .map(|uid| (uid, privileged.group.unwrap_or(uid)));
        let (operator, source) = resolve(named, existing_owner(dirs), sudo())
            .map_err(|reason| Error::Operator { reason })?;

        Ok(Self {
            euid,
            operator: Some(operator),
            source: Some(source),
        })
    }

    /// Whether this process has a privilege to hand down at all.
    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    /// An instance that is not root, which is what every test runs as and the
    /// case where the module's default needs no drop at all.
    ///
    /// Written out rather than discovered so a test says the same thing on a
    /// machine where it happens to be run as root.
    #[cfg(all(test, feature = "singbox-core"))]
    pub(crate) fn not_root() -> Self {
        Self {
            euid: 501,
            operator: None,
            source: None,
        }
    }

    /// A root instance that was told whose files it is holding.
    #[cfg(all(test, feature = "singbox-core"))]
    pub(crate) fn root_as(uid: u32, gid: u32) -> Self {
        Self {
            euid: 0,
            operator: Some((uid, gid)),
            source: Some(Source::Named),
        }
    }

    /// Give the directories back to the user they belong to.
    ///
    /// Called once, before anything is read: a run that started as root writes
    /// files root owns, and an operator who then runs without a privilege would
    /// find their own instance unreadable.
    pub fn settle_files(&self, dirs: &[&Path]) {
        let Some((uid, gid)) = self.operator else {
            return;
        };
        if self.is_root() {
            tracing::info!("running as root: what this instance writes belongs to {uid}:{gid}");
        }

        for dir in dirs {
            // Not fatal: whatever could not be handed back is a file somebody
            // gets told about by whoever cannot open it.
            if let Err(error) = crate::fs::hand_back(dir, uid, gid) {
                tracing::warn!("{dir:?}: could not be handed back: {error}");
            }
        }

        // And everything written from here on is theirs as it is written: a
        // config file its owner cannot read is the same problem arriving again a
        // minute later.
        crate::fs::write_for(uid, gid);
    }
}

/// The first source that can answer, and which one it was.
fn resolve(
    named: Option<(u32, u32)>,
    existing: Option<(u32, u32)>,
    sudo: Option<(u32, u32)>,
) -> Result<((u32, u32), Source), &'static str> {
    if let Some(named) = named {
        return Ok((named, Source::Named));
    }
    if let Some(existing) = existing {
        return Ok((existing, Source::Existing));
    }
    if let Some(sudo) = sudo {
        return Ok((sudo, Source::Sudo));
    }

    Err(
        "started as root, and nothing says whose files it is holding: pass --user <uid> (and \
         --group <gid> when the group is a different number), point --data at a directory that \
         already belongs to the user, start it with `sudo -E` so SUDO_UID survives, or pass \
         `--user 0` to say the files are root's",
    )
}

/// The owner of a directory that is already there, which is whose files these
/// are by the only record an environment cannot change.
fn existing_owner(dirs: &[&Path]) -> Option<(u32, u32)> {
    dirs.iter().find_map(|dir| {
        let metadata = std::fs::metadata(dir).ok()?;

        Some((metadata.uid(), metadata.gid()))
    })
}

/// What the `sudo` that started this recorded, when it left it behind.
fn sudo() -> Option<(u32, u32)> {
    Some((number("SUDO_UID")?, number("SUDO_GID")?))
}

/// An environment variable that holds a number.
fn number(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_command_line_named_settles_it() {
        assert_eq!(
            resolve(Some((501, 20)), Some((9, 9)), Some((8, 8))),
            Ok(((501, 20), Source::Named))
        );
    }

    /// A directory is a record nobody can drop by changing an environment.
    #[test]
    fn an_existing_directory_beats_the_environment() {
        assert_eq!(
            resolve(None, Some((501, 20)), Some((8, 8))),
            Ok(((501, 20), Source::Existing))
        );
    }

    /// And the environment is what is left when there is nothing else.
    #[test]
    fn the_environment_is_the_last_source() {
        assert_eq!(
            resolve(None, None, Some((501, 20))),
            Ok(((501, 20), Source::Sudo))
        );
    }

    /// A root run that cannot be told whose files it holds does not guess.
    #[test]
    fn nothing_at_all_is_an_error() {
        assert!(resolve(None, None, None).is_err());
    }
}
