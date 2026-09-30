//! Running the core, and what it said while it ran.
//!
//! A process outlives the call that started it, so this is the one place in this
//! crate that holds something between calls: a [`Runner`] owns the child, the
//! lines it printed, and the last few ways it ended. Everything here is behind a
//! mutex because the threads that read the child's pipes run beside whatever
//! asked for its status.
//!
//! **The core speaks for itself.** Its output is kept exactly as it came — it is
//! the core's own voice, and rewriting it would be inventing facts — which means
//! a line it printed about this machine (an interface, an address) is kept as
//! such. Nothing *this* module writes into that log ever carries a credential:
//! the only line it adds is the one about the way the process ended.
//!
//! **Stopping is a request, then a decision.** The process is asked to end with
//! `SIGTERM` — sing-box closes what it opened and exits by itself — and only a
//! process that ignores that is ended with `SIGKILL`. Both signals go to the pid
//! the child was started with, beside a reaper thread that waits for it: while
//! that thread has not reaped the child, its pid is still this process's, so the
//! window in which a signal could reach something else is the one between the
//! child's exit and its reaping.
//!
//! This module is Unix-only, and so is the platform naming in [`crate::core`]:
//! signals are how a process is asked to stop, and there is no second way.

use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::process::{kill_process, Pid, Signal};
use serde::Serialize;

use crate::core::Error;

/// How many lines of the core's own output are kept.
pub const LOG_LINES: usize = 200;

/// How much of one line is kept.
///
/// A core that prints a megabyte on one line is a core whose log would otherwise
/// be that megabyte; the beginning of a line is where the thing it is about is.
pub const LOG_LINE_CHARS: usize = 600;

/// How many exits are remembered.
pub const EXITS: usize = 8;

/// The command sing-box is run by.
///
/// `sing-box -D <work> -c <config> run`: the working directory is where its own
/// cache goes, the configuration is a file rather than an argument, and `run` is
/// the subcommand. Which binary that is belongs to the caller.
pub fn command(binary: &Path, config: &Path, work: &Path) -> Command {
    let mut command = Command::new(binary);
    command.arg("-D").arg(work).arg("-c").arg(config).arg("run");

    command
}

/// What is known about the process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// Whether it is running now.
    pub running: bool,
    /// Its pid, while it is.
    pub pid: Option<u32>,
    /// When it was started, in seconds since the epoch.
    pub started_at: Option<i64>,
    /// The last ways it ended, oldest first.
    pub exits: Vec<Exit>,
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Exit {
    /// When, in seconds since the epoch.
    pub at: i64,
    /// The status it left with, when it left with one.
    pub code: Option<i32>,
    /// The signal that ended it, when one did.
    pub signal: Option<i32>,
}

impl Exit {
    /// What to say about it, in one line.
    ///
    /// Prefixed, because the log holds two voices: the core's, forwarded as it
    /// came, and this module's, which is the only one that can be recognised.
    fn line(&self) -> String {
        match (self.code, self.signal) {
            (Some(code), _) => format!("{MARK} the core exited with status {code}"),
            (_, Some(signal)) => format!("{MARK} the core was ended by signal {signal}"),
            _ => format!("{MARK} the core ended"),
        }
    }
}

/// What a line this module wrote starts with.
pub const MARK: &str = "[suba]";

/// What the threads share.
#[derive(Default)]
struct State {
    pid: Option<u32>,
    started_at: Option<i64>,
    exits: VecDeque<Exit>,
    log: VecDeque<String>,
}

/// A core process, and what it printed.
#[derive(Default)]
pub struct Runner {
    state: Arc<Mutex<State>>,
    /// Signalled whenever the child ends, so a stop can wait for it.
    ended: Arc<Condvar>,
}

impl Runner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a process.
    ///
    /// One at a time: a second process beside the first would fight it for the
    /// same listening sockets, and the caller would have two pids for one
    /// configuration.
    pub fn spawn(&self, mut command: Command) -> Result<u32, Error> {
        let mut child = {
            let mut state = self.lock();

            if let Some(pid) = state.pid {
                return Err(Error::Running { pid });
            }

            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let child = command.spawn().map_err(|_| Error::Run {
                reason: "the process could not be started",
            })?;

            state.log.clear();
            state.pid = Some(child.id());
            state.started_at = Some(now());

            child
        };

        // The child's own voice, read as it comes.
        for stream in [
            child
                .stdout
                .take()
                .map(|stream| Box::new(stream) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|stream| Box::new(stream) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let state = Arc::clone(&self.state);
            thread::spawn(move || keep_reading(state, stream));
        }

        // Whoever waits for the child is what tells the others it is gone.
        let pid = child.id();
        let state = Arc::clone(&self.state);
        let ended = Arc::clone(&self.ended);
        thread::spawn(move || {
            let exit = match child.wait() {
                Ok(status) => Exit {
                    at: now(),
                    code: status.code(),
                    signal: signal_of(&status),
                },
                Err(_) => Exit {
                    at: now(),
                    code: None,
                    signal: None,
                },
            };

            {
                let mut state = state.lock().expect("the state");
                state.pid = None;
                state.exits.push_back(exit);
                while state.exits.len() > EXITS {
                    state.exits.pop_front();
                }
                state.log.push_back(exit.line());
            }

            ended.notify_all();
        });

        Ok(pid)
    }

    /// Ask the process to end, and make sure it does.
    ///
    /// Nothing to stop is not a failure: a caller that stops what is already
    /// stopped wanted it stopped, and it is.
    pub fn stop(&self, patience: Duration) -> Result<(), Error> {
        let Some(pid) = self.lock().pid else {
            return Ok(());
        };
        let pid = Pid::from_raw(pid as i32).ok_or(Error::Run {
            reason: "the pid is not a pid",
        })?;

        // Asked first: a core that is closing connections is a core that is
        // doing what the operator wants.
        kill_process(pid, Signal::TERM).map_err(|_| Error::Run {
            reason: "the process could not be asked to stop",
        })?;

        if self.wait_for_end(patience) {
            return Ok(());
        }

        kill_process(pid, Signal::KILL).map_err(|_| Error::Run {
            reason: "the process could not be stopped",
        })?;

        if self.wait_for_end(patience) {
            return Ok(());
        }

        Err(Error::Run {
            reason: "the process did not stop",
        })
    }

    /// What the process is doing.
    pub fn status(&self) -> Status {
        let state = self.lock();

        Status {
            running: state.pid.is_some(),
            pid: state.pid,
            started_at: state.started_at,
            exits: state.exits.iter().copied().collect(),
        }
    }

    /// The last `tail` lines the core printed, oldest first.
    pub fn log(&self, tail: usize) -> Vec<String> {
        let state = self.lock();

        state
            .log
            .iter()
            .skip(state.log.len().saturating_sub(tail))
            .cloned()
            .collect()
    }

    /// Wait until the child has ended, or the patience runs out.
    ///
    /// `true` when it ended. The condition is the pid being gone, which the
    /// thread that reaped it clears.
    fn wait_for_end(&self, patience: Duration) -> bool {
        let state = self.lock();
        let (state, _) = self
            .ended
            .wait_timeout_while(state, patience, |state| state.pid.is_some())
            .expect("the state");
        let ended = state.pid.is_none();
        drop(state);

        ended
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("the state")
    }
}

/// Keep reading one of the child's streams into the log.
fn keep_reading(state: Arc<Mutex<State>>, stream: Box<dyn Read + Send>) {
    for line in BufReader::new(stream).split(b'\n') {
        let Ok(line) = line else {
            break;
        };

        // The bytes are the core's, and a core may print a byte that is not
        // text: kept as text rather than dropped.
        let line = String::from_utf8_lossy(&line);
        let line = line.trim_end_matches('\r');
        let line: String = line.chars().take(LOG_LINE_CHARS).collect();

        let mut state = state.lock().expect("the state");
        state.log.push_back(line);
        while state.log.len() > LOG_LINES {
            state.log.pop_front();
        }
    }
}

/// When it is, in seconds since the epoch.
///
/// The one clock this crate reads: a process outlives the call that started it,
/// so there is no caller to hand a time in from.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

/// The signal that ended a process, when one did.
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;

    status.signal()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process this test can control: a shell that runs what it is told.
    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);

        command
    }

    fn wait_until_stopped(runner: &Runner) {
        for _ in 0..200 {
            if !runner.status().running {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        panic!("the process did not stop on its own");
    }

    /// What the core itself printed, without the lines this module adds.
    fn core_said(runner: &Runner) -> Vec<String> {
        runner
            .log(LOG_LINES + 100)
            .into_iter()
            .filter(|line| !line.starts_with(MARK))
            .collect()
    }

    /// Wait until the process has said something, which is the only proof that
    /// whatever it was going to set up first has been set up.
    fn wait_for(runner: &Runner, line: &str) {
        for _ in 0..200 {
            if runner.log(LOG_LINES).iter().any(|said| said == line) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        panic!("the process never said {line:?}");
    }

    #[test]
    fn the_command_is_the_one_sing_box_understands() {
        let command = command(
            Path::new("/versions/1.14.2/bin/sing-box"),
            Path::new("/data/sing-box/config/config.json"),
            Path::new("/data/sing-box/data"),
        );

        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            args,
            [
                "-D",
                "/data/sing-box/data",
                "-c",
                "/data/sing-box/config/config.json",
                "run"
            ]
        );
        assert_eq!(
            command.get_program().to_string_lossy(),
            "/versions/1.14.2/bin/sing-box"
        );
    }

    #[test]
    fn a_process_that_ends_is_remembered_along_with_what_it_said() {
        let runner = Runner::new();

        let pid = runner
            .spawn(shell("echo one; echo two 1>&2; exit 3"))
            .expect("a process");
        assert!(pid > 0);

        wait_until_stopped(&runner);
        let status = runner.status();

        assert!(!status.running);
        assert_eq!(status.pid, None);
        assert!(status.started_at.is_some());
        assert_eq!(status.exits.len(), 1);
        assert_eq!(status.exits[0].code, Some(3));
        assert_eq!(status.exits[0].signal, None);

        let log = runner.log(LOG_LINES);
        assert!(log.contains(&"one".to_string()), "{log:?}");
        assert!(log.contains(&"two".to_string()), "{log:?}");
        // The one line this module adds, among the core's own: what it does not
        // say in the rest of them is how it ended.
        assert!(
            log.contains(&format!("{MARK} the core exited with status 3")),
            "{log:?}"
        );
    }

    #[test]
    fn a_second_process_is_refused_while_one_is_running() {
        let runner = Runner::new();

        let pid = runner.spawn(shell("exec sleep 30")).expect("a process");

        let refused = runner.spawn(shell("exec sleep 30"));

        assert_eq!(refused, Err(Error::Running { pid }));
        assert_eq!(runner.status().exits.len(), 0);

        runner.stop(Duration::from_secs(2)).expect("a stop");
    }

    #[test]
    fn stopping_asks_first_and_the_process_answers() {
        let runner = Runner::new();

        let pid = runner.spawn(shell("exec sleep 30")).expect("a process");
        assert_eq!(runner.status().pid, Some(pid));

        runner.stop(Duration::from_secs(2)).expect("a stop");

        let status = runner.status();
        assert!(!status.running);
        // Asked, not forced: a process that ends on its own says so with TERM.
        assert_eq!(status.exits.len(), 1);
        assert_eq!(status.exits[0].signal, Some(15));

        // Stopping what is already stopped is what a caller wanted anyway.
        runner.stop(Duration::from_millis(10)).expect("a stop");
    }

    #[test]
    fn a_process_that_ignores_the_request_is_ended_anyway() {
        let runner = Runner::new();

        // A shell that swallows TERM and keeps going, so only the second signal
        // can end it. It says when the trap is in place: a signal that arrives
        // before that is a signal the shell was not yet ignoring.
        runner
            .spawn(shell("trap '' TERM; echo ready; while :; do sleep 1; done"))
            .expect("a process");
        wait_for(&runner, "ready");

        runner.stop(Duration::from_millis(200)).expect("a stop");

        let status = runner.status();
        assert!(!status.running);
        assert_eq!(status.exits.len(), 1);
        assert_eq!(status.exits[0].signal, Some(9));
    }

    #[test]
    fn the_log_keeps_the_last_lines_and_only_so_much_of_one() {
        let runner = Runner::new();

        // More lines than the ring holds, and one that is longer than a line is
        // allowed to be.
        let long = "x".repeat(LOG_LINE_CHARS + 100);
        runner
            .spawn(shell(&format!(
                "for i in $(seq 1 {}); do echo line $i; done; echo {long}",
                LOG_LINES + 100
            )))
            .expect("a process");
        wait_until_stopped(&runner);

        let said = core_said(&runner);
        // The ring dropped the beginning and kept the end, and the long line is
        // cut where a line is cut.
        assert!(
            said.len() <= LOG_LINES && said.len() >= LOG_LINES - 2,
            "{}",
            said.len()
        );
        assert_eq!(said[said.len() - 2], format!("line {}", LOG_LINES + 100));
        assert_eq!(said[said.len() - 1].chars().count(), LOG_LINE_CHARS);
        assert!(said[said.len() - 1].starts_with('x'));
    }

    #[test]
    fn a_log_can_be_asked_for_a_tail() {
        let runner = Runner::new();

        runner
            .spawn(shell("for i in 1 2 3 4 5; do echo line $i; done"))
            .expect("a process");
        wait_until_stopped(&runner);

        assert_eq!(
            core_said(&runner),
            ["line 1", "line 2", "line 3", "line 4", "line 5"]
        );

        // A tail is a tail of the whole log, whichever voice the lines are in.
        let all = runner.log(LOG_LINES);
        assert_eq!(all.len(), 6);
        assert_eq!(runner.log(1), all[5..]);
        assert_eq!(runner.log(0), Vec::<String>::new());
    }
}
