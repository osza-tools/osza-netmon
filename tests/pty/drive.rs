// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// A test binary (a [[test]] target, `harness = false` — the netns
// target's precedent, see Cargo.toml): cargo compiles such targets
// without `--cfg test`, so the clippy.toml test allowances do not
// apply and the crate-wide denies from [lints.clippy] fire on the
// scenario assertions. The relief below is scoped to exactly the pty
// harness files, like tests/netns/main.rs before them; every
// production module under src/ keeps the full deny set.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! The `script(1)` pty driver (task T-301 §6): the harness choice,
//! documented.
//!
//! The pinned `nix` carries only the `net` and `process` features —
//! its pty and termios modules need `term`, which the task card's
//! §5.3 pre-authorization does not cover (it lists exactly the two
//! signal-handling options, and ADR-018 chose `signal-hook`), so the
//! sanctioned fallback is the `script(1)` utility: no new
//! dev-dependencies, no new crate features, a real pty pair with the
//! application as its session leader on the slave.
//!
//! # How each requirement is met through `script`
//!
//! * **A real pty**: `script -qefc <command> /dev/null` allocates
//!   one; the command runs as a session leader with the slave as its
//!   controlling terminal (`-e` propagates the command's exit code,
//!   `-f` flushes output per chunk, `-q` drops the banners).
//! * **Deterministic initial size**: the wrapper command's first
//!   step is `stty rows 24 cols 80` on the slave (§6's resize test
//!   starts at exactly 80×24).
//! * **The child's pid** (signals, resizes, the idle sampling): the
//!   wrapper writes its own pid to a file; the application is its
//!   only foreground child, found through
//!   `/proc/<pid>/task/<pid>/children` — pure `/proc` reads, no
//!   pgrep races.
//! * **Mid-session resizes**: `stty -F /proc/<app>/fd/0 rows R cols
//!   C` — a `TIOCSWINSZ` on the slave, which delivers `SIGWINCH` to
//!   the foreground group and a `Resize` event to the app (§6's
//!   80×24 → 79×24 → 80×24 drive).
//! * **Signals**: `kill -TERM/-HUP <app pid>` (the `kill(1)`
//!   utility).
//! * **"Raw mode off" observed behaviorally**: while the app holds
//!   raw mode the tty driver does not echo; after a clean restore it
//!   does again. The wrapper keeps the pty alive for a trailing
//!   sleep after the app exits, and the driver's echo probe sends
//!   one byte and requires it back — ECHO restored means not raw.
//! * **"Capture off" observed from the stream**: the app's own
//!   output must contain the crossterm mouse-capture escape
//!   (`ESC[?1000h`) at init and its counterpart (`ESC[?1000l`)
//!   after it on every exit path — the driver asserts the *last*
//!   capture sequence in the byte stream is a disable.

use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

/// The crossterm mouse-capture markers (the first of the four
/// sequences each macro writes; the driver matches the pair).
const CAPTURE_ENABLE: &[u8] = b"\x1b[?1000h";
const CAPTURE_DISABLE: &[u8] = b"\x1b[?1000l";
/// The alternate-screen enter/leave markers.
const ALT_ENTER: &[u8] = b"\x1b[?1049h";
const ALT_LEAVE: &[u8] = b"\x1b[?1049l";

/// One `script(1)` session around a command.
pub struct PtySession {
    /// script's pid (for the hard kill of a hung scenario).
    script_pid: u32,
    stdin: std::process::ChildStdin,
    output: Arc<Mutex<Vec<u8>>>,
    exit_rx: mpsc::Receiver<ExitStatus>,
    pid_file: PathBuf,
    /// The shell's pid (the wrapper's `$$`).
    shell_pid: u32,
    /// The scenario label (diagnostics on failure).
    label: String,
}

impl PtySession {
    /// Spawns `command` (an already-quoted shell command string) on a
    /// fresh pty at 80×24, with `tail` seconds of trailing pty
    /// lifetime after the command exits (the echo-probe window).
    pub fn spawn(label: &str, command: &str, tail: u64) -> Self {
        Self::spawn_inner(label, command, tail, None)
    }

    /// The netns variant (§14.3.7): the pty session runs inside
    /// `unshare --user --map-root-user --net` after `setup` (the
    /// synthetic-network bring-up) — everything else identical.
    pub fn spawn_netns(label: &str, setup: &str, command: &str, tail: u64) -> Self {
        Self::spawn_inner(label, command, tail, Some(setup))
    }

    fn spawn_inner(label: &str, command: &str, tail: u64, netns_setup: Option<&str>) -> Self {
        let pid_file =
            std::env::temp_dir().join(format!("osza-t301-pty-{label}-{}.pid", std::process::id()));
        let wrapper = format!(
            "echo $$ > {}; stty rows 24 cols 80; {}; s=$?; sleep {}; exit $s",
            pid_file.display(),
            command,
            tail
        );
        // Without a namespace the wrapper runs directly under script;
        // with one, the bring-up runs first and script becomes the
        // session's final exec (same wrapper, same pty).
        let mut command_line = match netns_setup {
            None => {
                let mut argv = vec!["script".to_owned(), "-qefc".to_owned(), wrapper];
                argv.push("/dev/null".to_owned());
                argv
            }
            Some(setup) => vec![
                "unshare".to_owned(),
                "--user".to_owned(),
                "--map-root-user".to_owned(),
                "--net".to_owned(),
                "sh".to_owned(),
                "-c".to_owned(),
                format!("{setup} && exec script -qefc '{wrapper}' /dev/null"),
            ],
        };
        let program = command_line.remove(0);
        let mut child = Command::new(&program)
            .args(&command_line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("spawning {program} failed: {error}"));
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");

        // The accumulating output: a reader thread drains script's
        // stdout into a shared buffer (a full pipe would wedge the
        // session). The handle is deliberately dropped: the thread
        // ends with the stream, the buffer outlives it.
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        let _reader = std::thread::spawn(move || {
            let mut stream = stdout;
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sink.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .extend_from_slice(&chunk[..n]);
                    }
                }
            }
        });

        // The exit status: a waiter thread, so the driver can poll.
        let script_pid = child.id();
        let (exit_tx, exit_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let status = child.wait().expect("script is our child");
            let _ = exit_tx.send(status);
        });

        // The wrapper's pid: the file appears within moments.
        let shell_pid = wait_for_pid_file(&pid_file);

        PtySession {
            script_pid,
            stdin,
            output,
            exit_rx,
            pid_file,
            shell_pid,
            label: label.to_owned(),
        }
    }

    /// The accumulated output so far (copied).
    pub fn output(&self) -> Vec<u8> {
        self.output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Sends raw bytes to the pty (they reach the app's stdin).
    pub fn send(&mut self, bytes: &[u8]) {
        if let Err(error) = self.stdin.write_all(bytes) {
            // Diagnostics first: the full output is preserved for the
            // post-mortem, the tail is inlined.
            let output = self.output();
            let debug_path = std::env::temp_dir().join(format!(
                "osza-t301-pty-{label}-full.out",
                label = self.label
            ));
            let _ = std::fs::write(&debug_path, &output);
            let tail: String = String::from_utf8_lossy(&output[output.len().saturating_sub(300)..])
                .escape_debug()
                .to_string();
            panic!(
                "script's stdin broke: {error}; output tail: {tail} \
                 (full output: {})",
                debug_path.display()
            );
        }
        if let Err(error) = self.stdin.flush() {
            panic!("flushing script's stdin failed: {error}");
        }
    }

    /// Waits until the accumulated output contains `needle`, polling
    /// at a small granularity.
    pub fn wait_for(&self, needle: &[u8], timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if contains(&self.output(), needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let found = contains(&self.output(), needle);
        if !found {
            // Diagnostics: the full output is preserved next to the
            // scenario's temp files; the tail is inlined.
            let output = self.output();
            let debug_path = std::env::temp_dir().join(format!(
                "osza-t302-pty-{label}-waitfull.out",
                label = self.label
            ));
            let _ = std::fs::write(&debug_path, &output);
            let tail: String = String::from_utf8_lossy(&output[output.len().saturating_sub(400)..])
                .escape_debug()
                .to_string();
            panic!(
                "wait_for({needle:?}) timed out after {timeout:?}; tail: {tail} \
                 (full output: {})",
                debug_path.display()
            );
        }
        found
    }

    /// The application's pid: the wrapper shell's only foreground
    /// child, read from `/proc` (pure std). `None` before the app
    /// spawns or after it exits.
    pub fn app_pid(&self) -> Option<u32> {
        let children = std::fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            self.shell_pid, self.shell_pid
        ))
        .ok()?;
        children.split_whitespace().next()?.parse().ok()
    }

    /// Resizes the pty through the app's own tty (`TIOCSWINSZ` on the
    /// slave; the kernel delivers `SIGWINCH` to the foreground
    /// group).
    pub fn resize(&self, cols: u16, rows: u16) {
        let pid = self.app_pid().expect("the app is running");
        let tty = std::fs::read_link(format!("/proc/{pid}/fd/0"))
            .expect("the app's stdin is its controlling tty");
        let output = Command::new("stty")
            .arg("-F")
            .arg(&tty)
            .arg("cols")
            .arg(cols.to_string())
            .arg("rows")
            .arg(rows.to_string())
            .output()
            .expect("stty exists");
        assert!(
            output.status.success(),
            "stty could not resize {tty:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Sends a signal to the application (`kill(1)`).
    pub fn signal(&self, which: &str) {
        let pid = self.app_pid().expect("the app is running");
        let status = Command::new("kill")
            .arg(which)
            .arg(pid.to_string())
            .status()
            .expect("kill exists");
        assert!(status.success(), "kill {which} {pid} delivered");
    }

    /// Waits for `script` to exit and returns the propagated status
    /// code of the wrapped command.
    pub fn wait_exit(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(status) = self.exit_rx.try_recv() {
                return exit_code(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// The echo probe (the "raw mode off" observation): with the
    /// trailing `sleep` keeping the pty alive, one byte sent after
    /// the app exited must come back — ECHO is a cooked-mode driver
    /// behavior, so its return proves the restore.
    pub fn echo_probe(&mut self) -> bool {
        self.send(b"z");
        self.wait_for(b"z", Duration::from_secs(3))
    }

    /// Asserts the capture discipline on the stream: the enable
    /// sequence appears at init, and the last capture sequence in the
    /// output is a disable (every exit path); the alternate screen
    /// was entered and left.
    pub fn assert_capture_restored(&self) {
        let output = self.output();
        let enable = last_position(&output, CAPTURE_ENABLE);
        let disable = last_position(&output, CAPTURE_DISABLE);
        assert!(enable.is_some(), "mouse capture was enabled at init");
        let (enable, disable) = (
            enable.expect("checked"),
            disable.expect("the disable sequence is in the stream after the enable"),
        );
        assert!(
            disable > enable,
            "the last capture sequence is the disable (enable@{enable}, disable@{disable})"
        );
        assert!(
            contains(&output, ALT_ENTER),
            "the alternate screen was entered"
        );
        assert!(
            contains(&output, ALT_LEAVE),
            "the alternate screen was left"
        );
    }

    /// Kills the session (a hung scenario must not hang the suite).
    pub fn kill(&mut self) {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(format!("-{pid}", pid = self.script_pid))
            .status();
        // Reap whatever the waiter thread has seen.
        let _ = self.wait_exit(Duration::from_secs(2));
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Best effort: never leave a script running behind a failed
        // scenario (the suite's own failure report comes first).
        let _ = std::fs::remove_file(&self.pid_file);
    }
}

fn wait_for_pid_file(path: &PathBuf) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the wrapper never wrote its pid file: {}", path.display());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    last_position(haystack, needle).is_some()
}

fn last_position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|start| &haystack[*start..*start + needle.len()] == needle)
}

fn exit_code(status: ExitStatus) -> Option<i32> {
    status.code()
}
