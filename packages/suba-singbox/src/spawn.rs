//! Starting a core binary that this machine has just written.
//!
//! Linux refuses `execve` with `ETXTBSY` while any process still holds a
//! writable descriptor to that inode. An install writes the binary and starts
//! it on the next step, and the two can overlap: between one thread's `write`
//! and its `close` the file is briefly not executable. macOS has no such race,
//! and it is not a fault in the archive — the same bytes start a moment later.
//!
//! So a start refused for exactly that reason is retried, briefly and a bounded
//! number of times. Nothing else is retried, and a binary still busy when the
//! attempts run out is reported as the failure it is. Every start this crate
//! makes goes through here, so no caller has to remember the rule.

use std::io;
use std::process::{Child, Command, Output};
use std::thread;
use std::time::Duration;

/// How many times one start is attempted, and how long to wait between tries.
///
/// What the wait is for is the tail of another thread's `write`, which is
/// microseconds. These numbers are far past that, and bounded so that a file
/// that is genuinely busy is reported rather than waited on forever.
const ATTEMPTS: u32 = 20;
const PAUSE: Duration = Duration::from_millis(1);

/// Whether `execve` was refused only because the file was still being written.
fn busy(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ExecutableFileBusy
}

/// Start `command` and hand back the child it became.
pub(crate) fn child(mut command: Command) -> io::Result<Child> {
    retrying(|| command.spawn())
}

/// Run `command` to completion and collect what it wrote.
pub(crate) fn output(mut command: Command) -> io::Result<Output> {
    retrying(|| command.output())
}

/// Apply `start` until it is not refused for the one reason that passes.
///
/// Retrying an attempt that failed before `execve` reached a program is safe:
/// nothing ran, so nothing ran twice.
fn retrying<T>(mut start: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    for _ in 1..ATTEMPTS {
        match start() {
            Err(error) if busy(&error) => thread::sleep(PAUSE),
            result => return result,
        }
    }

    start()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::time::Instant;

    /// A directory of this test's own, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "suba-spawn-{}-{:?}",
                std::process::id(),
                thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("a temporary directory");

            Self(path)
        }

        /// A script at `name` that exits with `code`.
        fn tool(&self, name: &str, code: u8) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, format!("#!/bin/sh\nexit {code}\n")).expect("a script");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");

            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The reason this module exists: a writable descriptor held on the binary
    /// makes Linux refuse `execve` until it is closed. Without the retry the
    /// very first attempt is refused, which is what the red run showed.
    #[test]
    fn a_binary_with_a_writer_still_open_is_started_once_the_writer_lets_go() {
        let scratch = Scratch::new();
        let tool = scratch.tool("held.sh", 0);

        // Held for the length of the start and no longer: the module is given
        // the same race the kernel does, on purpose.
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(&tool)
            .expect("a writable handle");

        let released = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            drop(writer);
        });

        let started =
            child(Command::new(&tool)).expect("the binary starts once the writer is gone");
        let status = started.wait_with_output().expect("it is waited for");
        released.join().expect("the writer thread");

        assert!(status.status.success(), "the script ran and exited zero");
    }

    /// The other half of the rule: only that one refusal is waited out, so a
    /// binary that is simply not there is refused without the pause.
    #[test]
    fn a_binary_that_is_not_there_is_refused_at_once() {
        let scratch = Scratch::new();
        let missing = scratch.0.join("absent.sh");

        let started = Instant::now();
        let refused = child(Command::new(&missing)).expect_err("there is no such binary");
        let took = started.elapsed();

        assert_eq!(refused.kind(), io::ErrorKind::NotFound);
        assert!(
            took < PAUSE * ATTEMPTS / 2,
            "a missing binary must not be waited out like a busy one; it took {took:?}"
        );
    }

    /// A binary the kernel will not execute at all is refused in its own words,
    /// not folded into the one refusal this module waits out.
    #[test]
    fn a_binary_that_is_not_executable_says_exactly_that() {
        let scratch = Scratch::new();
        let path = scratch.0.join("plain.txt");
        fs::write(&path, "not a program").expect("a file");

        let started = Instant::now();
        let refused = child(Command::new(&path)).expect_err("it cannot be executed");
        let took = started.elapsed();

        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert!(took < PAUSE * ATTEMPTS / 2, "and is not waited out either");
    }

    /// A start is not run twice: what the caller asked to happen happens once.
    #[test]
    fn output_is_collected_from_the_one_run_that_succeeded() {
        let scratch = Scratch::new();
        let tool = scratch.tool("said.sh", 0);

        let ran = output(Command::new(&tool)).expect("the binary runs");

        assert!(ran.status.success());
        assert!(ran.stdout.is_empty(), "the script prints nothing");
    }
}
