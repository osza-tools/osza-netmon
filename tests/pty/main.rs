// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// A test binary (`harness = false` — the netns target's precedent):
// compiled without `--cfg test`, so the crate-wide clippy denies fire
// on scenario assertions; the relief is scoped to the pty harness
// files exactly as in tests/netns/main.rs.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! The T-301/T-302 pty integration harness (task cards §6): the
//! acceptance evidence for the terminal lifecycle and the T-302
//! screens, driven through real ptys.
//!
//! The harness is a custom test binary (`harness = false`, the netns
//! target's own precedent) because its `--fake-session` and
//! `--arp-listener` modes re-exec this executable (as the fake-source
//! application under `script(1)`, and as the netns egress listener),
//! which a generated libtest main cannot dispatch; and the scenarios
//! are sequential by nature (each drives a process for seconds).
//!
//! # Sentinel discipline (T-301 decision 12)
//!
//! ratatui renders by cell diff — a word is written as one contiguous
//! run, but the *space* between words matches the blank buffer and is
//! skipped, so multi-word literals never appear contiguously in the
//! stream. All sentinels are single words, unique per screen:
//! `Authorization` (the notice), `Choose` (the scope list),
//! `confirmation` (a dialog), `Dashboard` (the placeholder), `small`
//! (the too-small overlay). The device count is matched by its
//! cursor-addressed write (`ESC[2;10H` + digits — the count cell is
//! always reached by a move: the space before it never changes).
//!
//! # Environment isolation
//!
//! Every spawned application (real or fake) runs with
//! `XDG_CONFIG_HOME` pointed at a per-scenario empty directory: the
//! real binary and the fake session read the notice-ack record at
//! startup and write it on `y` (T-302), and a scenario's outcome must
//! never depend on (or touch) the runner's real configuration.
//!
//! # Scenarios
//!
//! 1–5. The five T-301 restore cases (`q`, the fault seam's error and
//!    panic arms, SIGTERM, SIGHUP): exit codes and the restored
//!    terminal, unchanged.
//! 6. `resize_too_small_toggle` — the too-small overlay on the real
//!    screens, recovery without a state reset.
//! 7. `smoke_fake_source` — the end-to-end smoke over the reviewed
//!    fakes (T-205 AC-5's variant under the pty): notice → `y` →
//!    scope → the FR-SC-07 typed `yes` → `Enter` → a nonzero live
//!    device count → `q`.
//! 8. `smoke_netns_real` — the same flow against the real binary in a
//!    network namespace with a veth pair (§14.3.7).
//! 9. `idle_cpu` — NFR-04: the real binary idle at the notice screen.
//! 10. `flow_first_run_ack` — §6's first run: the notice, `y`, the
//!     ack record written mode `0600` in the card-fixed format, the
//!     scope, and the confirmation of the **non-suggested** fake
//!     interface — the scan runs there (the exact device count).
//! 11. `flow_second_run` — a valid stored record: straight to scope.
//! 12. `flow_ack_reask` — a corrupt record and a version-mismatched
//!     record: the full notice again, both.
//! 13. `flow_ack_write_failure` — `XDG_CONFIG_HOME` pointing at a
//!     regular file: the write fails, the app continues (non-fatal).
//! 14. `netns_two_interface_egress` — the PQ-3 acceptance (§5.7.6):
//!     two veth pairs, the real binary, the NON-suggested interface
//!     confirmed — ARP egress lands **only** on the confirmed
//!     subnet's wire, zero egress pre-confirm, and `CapEff`/`CapPrm`
//!     zero while the TUI runs (SR-06).

mod drive;
mod fakes;
mod listener;

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use drive::PtySession;

/// The real binary under test (cargo sets this for the test target).
const BIN: &str = env!("CARGO_BIN_EXE_osza-netmon");

/// This harness's own path, resolved once (the `--fake-session` and
/// `--arp-listener` scenarios re-exec it under script/netns).
static SELF_EXE: OnceLock<String> = OnceLock::new();

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--fake-session" {
        // The fake-source application on this process's stdio (the
        // pty under script): exit 0 on the clean quit, 1 otherwise
        // (the assembly restored the terminal on every path).
        return match fakes::run_fake_session() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    if args.len() == 5 && args[1] == "--arp-listener" {
        // The netns egress listener (scenario 14): bound to one
        // interface, logging every frame it sees until the deadline.
        let seconds = match args[4].parse::<u64>() {
            Ok(seconds) if seconds > 0 => seconds,
            _ => return ExitCode::FAILURE,
        };
        return match listener::run(&args[2], &args[3], seconds) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    // The fake session and the listener re-exec this same executable;
    // resolve the path once (arg0 is unreliable).
    let self_exe = std::env::current_exe()
        .expect("current_exe works")
        .to_string_lossy()
        .into_owned();
    let _ = SELF_EXE.set(self_exe);

    /// One scenario: a name and its zero-argument runner.
    type Scenario = (&'static str, fn() -> Result<(), String>);

    let scenarios: [Scenario; 14] = [
        ("restore_normal_q", restore_normal_q),
        ("restore_error_exit", restore_error_exit),
        ("restore_panic", restore_panic),
        ("restore_sigterm", restore_sigterm),
        ("restore_sighup", restore_sighup),
        ("resize_too_small_toggle", resize_too_small_toggle),
        ("smoke_fake_source", smoke_fake_source),
        ("smoke_netns_real", smoke_netns_real),
        ("idle_cpu", idle_cpu),
        ("flow_first_run_ack", flow_first_run_ack),
        ("flow_second_run", flow_second_run),
        ("flow_ack_reask", flow_ack_reask),
        ("flow_ack_write_failure", flow_ack_write_failure),
        ("netns_two_interface_egress", netns_two_interface_egress),
    ];

    let started = Instant::now();
    let mut failures = 0usize;
    for (name, scenario) in scenarios {
        print!("pty scenario {name:<28} … ");
        match std::panic::catch_unwind(AssertUnwindSafe(scenario)) {
            Ok(Ok(())) => println!("ok"),
            Ok(Err(failure)) => {
                failures += 1;
                println!("FAIL: {failure}");
            }
            Err(panic) => {
                failures += 1;
                let message = panic
                    .downcast_ref::<&str>()
                    .map(std::string::ToString::to_string)
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic".to_owned());
                println!("FAIL (panic): {message}");
            }
        }
    }
    println!(
        "pty suite: {} scenario(s), {} failure(s), {:.1}s total",
        scenarios.len(),
        failures,
        started.elapsed().as_secs_f64()
    );
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Environment isolation (module docs): every app gets its own config
// ---------------------------------------------------------------------------

/// A fresh per-scenario config directory (the `XDG_CONFIG_HOME` the
/// spawned application sees). A unique subdirectory per call, so
/// repeat runs never inherit a stale ack record.
fn isolated_config(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "osza-t302-pty-{label}-{}-{}",
        std::process::id(),
        nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the scenario config dir is creatable");
    dir
}

/// A monotonically increasing discriminator for temp paths.
fn nanos() -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    now.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// The env-var prefix that isolates one spawned command's config.
fn xdg_prefix(dir: &std::path::Path) -> String {
    format!("XDG_CONFIG_HOME={} ", dir.display())
}

// ---------------------------------------------------------------------------
// The five restore scenarios (T-301 §6 a–e)
// ---------------------------------------------------------------------------

/// Spawns the real binary on a fresh pty (isolated config) and waits
/// for the first (notice) frame.
fn real_app(label: &str, tail: u64) -> PtySession {
    let config = isolated_config(label);
    let command = format!("{xdg}{BIN}", xdg = xdg_prefix(&config));
    let session = PtySession::spawn(label, &command, tail);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the first (notice) frame never appeared",
    );
    session
}

/// Spawns the real binary with the fault seam armed.
fn faulty_app(label: &str, fault: &str, tail: u64) -> PtySession {
    // The fault rides the environment through script to the binary.
    let command = format!("OSZA_NETMON_TEST_FAULT={fault} {BIN}");
    PtySession::spawn(label, &command, tail)
}

/// The full restore assertion set. Order matters: the echo probe must
/// run while the wrapper's trailing `sleep` still keeps the pty alive
/// (script exits only after it), so the app's own restore is observed
/// first (the alternate-screen leave in the stream), the probe runs
/// immediately after, and only then does the driver wait for script's
/// exit and the propagated code.
fn assert_restored(session: &mut PtySession, expected_exit: i32) -> Result<(), String> {
    // 1. The app restored: raw mode was disabled *before* the
    //    alternate screen was left (ratatui's restore order), so the
    //    leave marker is the app's last visible act.
    if !session.wait_for(b"\x1b[?1049l", Duration::from_secs(30)) {
        session.kill();
        return Err("the app never restored the terminal (no alt-screen leave)".to_owned());
    }
    // 2. Raw mode off, observed behaviorally: with the pty still
    //    alive (the trailing sleep), one byte must come back — ECHO
    //    is a cooked-mode driver behavior.
    if !session.echo_probe() {
        session.kill();
        return Err("the echo probe failed: raw mode (ECHO) was not restored".to_owned());
    }
    // 3. The exit code (script propagates it when the trailing sleep
    //    ends).
    let Some(code) = session.wait_exit(Duration::from_secs(30)) else {
        session.kill();
        return Err("the session never exited".to_owned());
    };
    if code != expected_exit {
        return Err(format!("exit code {code}, expected {expected_exit}"));
    }
    // 4. Capture off + the alternate-screen discipline, from the
    //    stream.
    session.assert_capture_restored();
    Ok(())
}

fn restore_normal_q() -> Result<(), String> {
    let mut session = real_app("normal-q", 4);
    session.send(b"q");
    assert_restored(&mut session, 0)
}

fn restore_error_exit() -> Result<(), String> {
    let mut session = faulty_app("error-exit", "error", 4);
    assert_or(
        session.wait_for(b"forced fault", Duration::from_secs(30)),
        "the forced error never surfaced",
    );
    assert_restored(&mut session, 1)
}

fn restore_panic() -> Result<(), String> {
    let mut session = faulty_app("panic", "panic", 4);
    assert_or(
        session.wait_for(b"forced panic", Duration::from_secs(30)),
        "the forced panic never surfaced",
    );
    assert_restored(&mut session, 101)
}

fn restore_sigterm() -> Result<(), String> {
    let mut session = real_app("sigterm", 4);
    session.signal("-TERM");
    assert_restored(&mut session, 0)
}

fn restore_sighup() -> Result<(), String> {
    let mut session = real_app("sighup", 4);
    session.signal("-HUP");
    assert_restored(&mut session, 0)
}

// ---------------------------------------------------------------------------
// The resize scenario (§6; the real screens since T-302)
// ---------------------------------------------------------------------------

fn resize_too_small_toggle() -> Result<(), String> {
    // On the fake session: a deterministic confirmable interface, so
    // the dashboard is guaranteed after the confirmation regardless of
    // the runner's interfaces.
    let mut session = fake_session("resize");
    drive_flow_to_dashboard(&mut session)?;
    // 80×24 → 79×24: the too-small overlay appears (NFR-08)…
    session.resize(79, 24);
    assert_or(
        session.wait_for(b"small", Duration::from_secs(20)),
        "the too-small overlay never appeared at 79 columns",
    );
    // …→ 80×24: the dashboard returns; the state never reset (the
    // screen is the dashboard again, not the notice or the scope
    // screen).
    session.resize(80, 24);
    assert_or(
        session.wait_for(b"Dashboard", Duration::from_secs(20)),
        "the dashboard never came back after the resize",
    );
    session.send(b"q");
    assert_restored(&mut session, 0)
}

// ---------------------------------------------------------------------------
// The smoke scenarios (§6)
// ---------------------------------------------------------------------------

/// Spawns this harness in `--fake-session` mode on a fresh pty, with
/// an isolated (empty) config directory.
fn fake_session(label: &str) -> PtySession {
    let config = isolated_config(label);
    let command = format!(
        "{xdg}{self} --fake-session",
        xdg = xdg_prefix(&config),
        self = SELF_EXE.get().expect("set in main")
    );
    let session = PtySession::spawn(label, &command, 4);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the fake session never showed the notice",
    );
    session
}

/// The fake session with an explicit config directory (the ack-flow
/// scenarios pre-seed or inspect it).
fn fake_session_in(label: &str, config: &std::path::Path) -> PtySession {
    let command = format!(
        "{xdg}{self} --fake-session",
        xdg = xdg_prefix(config),
        self = SELF_EXE.get().expect("set in main")
    );
    let session = PtySession::spawn(label, &command, 4);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the fake session never showed the notice",
    );
    session
}

/// notice → `y` → scope → the FR-SC-07 typed `yes` (the fake fixtures
/// use RFC 5737 documentation ranges — public networks) → `Enter` →
/// dashboard (the shared prefix of the smoke and resize scenarios).
fn drive_flow_to_dashboard(session: &mut PtySession) -> Result<(), String> {
    session.send(b"y");
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(20)),
        "y never acknowledged the notice",
    );
    drive_confirm_selected(session)
}

/// Enter → the dashboard for the currently selected (eligible) fake
/// interface. The fake session is **read-only** (no raw sockets), so
/// neither the FR-SC-06 cap rule nor the FR-SC-07 public-range rule
/// applies (both are active-mode-only): one `Enter` confirms.
fn drive_confirm_selected(session: &mut PtySession) -> Result<(), String> {
    session.send(b"\r");
    assert_or(
        session.wait_for(b"Dashboard", Duration::from_secs(20)),
        "Enter never confirmed the (read-only) scope",
    );
    Ok(())
}

/// Enter → the FR-SC-07 typed `yes` → Enter → the dashboard, for the
/// **active** real binary over a public (RFC 5737) network.
///
/// The dialog's sentinel is its box-drawing corner `┌` — the dialogs
/// are the only screens that draw box characters, so the cell-diff
/// writer can never skip that cell (word sentinels can split at cells
/// that happen to match the screen underneath; a border glyph cannot
/// match the list's plain text). The typed letters are not waited
/// for: a lost letter would leave the dialog open and the Dashboard
/// wait below would fail — the backstop.
fn drive_confirm_selected_public(session: &mut PtySession) -> Result<(), String> {
    session.send(b"\r");
    assert_or(
        session.wait_for(DIALOG_CORNER, Duration::from_secs(20)),
        "the FR-SC-07 confirmation never opened",
    );
    session.send(b"yes\r");
    assert_or(
        session.wait_for(b"Dashboard", Duration::from_secs(20)),
        "Enter never confirmed the scope",
    );
    Ok(())
}

/// The confirmation dialogs' top-left box corner (`┌`), the
/// split-proof dialog sentinel (drive helper docs).
const DIALOG_CORNER: &[u8] = "\u{250c}".as_bytes();

fn smoke_fake_source() -> Result<(), String> {
    let mut session = fake_session("smoke-fake");
    drive_flow_to_dashboard(&mut session)?;
    // The live device count: the confirmed interface's own device
    // plus the fake neighbor's — a nonzero count visible at least
    // once (AC-5).
    assert_or(
        wait_for_nonzero_devices(&session, Duration::from_secs(30)),
        "a nonzero device count never became visible",
    );
    session.send(b"q");
    assert_restored(&mut session, 0)
}

fn smoke_netns_real() -> Result<(), String> {
    // §14.3.7: probing only inside a synthetic network namespace — a
    // veth pair whose peer address the kernel answers ARP for. The
    // binary runs active (mapped-root has CAP_NET_RAW), the suggested
    // interface is veth0, and the sweep finds the peer.
    if !unshare_available() {
        return Err(
            "SKIPPED: unshare --user --map-root-user --net unavailable here \
             (the fake-source smoke is the fallback evidence)"
                .to_owned(),
        );
    }
    let config = isolated_config("smoke-netns");
    let setup = "ip link add veth0 type veth peer name veth1 \
                 && ip link set lo up \
                 && ip link set veth0 up \
                 && ip addr add 192.0.2.1/24 dev veth0 \
                 && ip link set veth1 up \
                 && ip addr add 192.0.2.5/24 dev veth1";
    let command = format!("{xdg}{BIN}", xdg = xdg_prefix(&config));
    let mut session = PtySession::spawn_netns("smoke-netns", setup, &command, 4);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the netns session never showed the notice",
    );
    session.send(b"y");
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(20)),
        "y never acknowledged the notice (netns)",
    );
    drive_confirm_selected_public(&mut session)?;
    // The real sweep: two passes over 253 addresses plus the listen
    // window — generous bound.
    assert_or(
        wait_for_nonzero_devices(&session, Duration::from_secs(90)),
        "real discovery never surfaced a nonzero device count",
    );
    session.send(b"q");
    assert_restored(&mut session, 0)
}

// ---------------------------------------------------------------------------
// The idle measurement (§5.7, NFR-04)
// ---------------------------------------------------------------------------

fn idle_cpu() -> Result<(), String> {
    // The duration: the card's 60 s locally, the documented ≥ 10 s CI
    // variant under the standard CI variable, an explicit override
    // through OSZA_PTY_IDLE_SECS.
    let seconds = idle_seconds();
    let config = isolated_config("idle");
    let command = format!("{xdg}{BIN}", xdg = xdg_prefix(&config));
    let mut session = PtySession::spawn("idle", &command, 1);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the idle session never showed the notice",
    );
    let Some(pid) = session.app_pid() else {
        session.kill();
        return Err("the idle app's pid was not found".to_owned());
    };

    let before = CpuSample::read(pid);
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(seconds));
    let elapsed = started.elapsed().as_secs_f64();
    let after = CpuSample::read(pid);

    session.send(b"q");
    assert_restored(&mut session, 0)?;

    let cpu_ticks = after.cpu_ticks.saturating_sub(before.cpu_ticks);
    let wakeups = after.voluntary.saturating_sub(before.voluntary);
    let hz = clk_tck();
    let cpu_percent = cpu_ticks as f64 / f64::from(hz) / elapsed * 100.0;
    let wakeups_per_second = wakeups as f64 / elapsed;
    println!(
        "\n    idle {seconds}s: utime+stime {cpu_ticks} ticks ({cpu_percent:.3}% of one core), \
         {wakeups} voluntary wake-ups ({wakeups_per_second:.1}/s) over {elapsed:.1}s",
    );
    if cpu_percent >= 1.0 {
        return Err(format!(
            "idle CPU {cpu_percent:.3}% of one core exceeds the 1% budget"
        ));
    }
    if wakeups_per_second > 100.0 {
        return Err(format!(
            "{wakeups_per_second:.1} wake-ups/s looks like a spin (budget 100)"
        ));
    }
    Ok(())
}

fn idle_seconds() -> u64 {
    if let Ok(text) = std::env::var("OSZA_PTY_IDLE_SECS")
        && let Ok(value) = text.parse::<u64>()
        && value >= 10
    {
        return value;
    }
    if std::env::var("CI").is_ok() { 10 } else { 60 }
}

/// `/proc/<pid>/stat` utime+stime (fields 14+15, after the last `)`)
/// and the **process-wide** voluntary context switches (the sum over
/// every task's `/proc/<pid>/task/<tid>/status` — the plain status
/// file would count only the main thread).
struct CpuSample {
    cpu_ticks: u64,
    voluntary: u64,
}

impl CpuSample {
    fn read(pid: u32) -> Self {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("the app is alive");
        let after_comm = stat
            .rsplit(')')
            .next()
            .expect("the stat line has a comm field");
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // Fields 14 (utime) and 15 (stime) are the 12th and 13rd
        // whitespace-separated words after ") " (field 3 is state).
        let utime = fields[11].parse::<u64>().expect("utime parses");
        let stime = fields[12].parse::<u64>().expect("stime parses");
        let mut voluntary = 0u64;
        let task_dir = format!("/proc/{pid}/task");
        if let Ok(tasks) = std::fs::read_dir(&task_dir) {
            for task in tasks.flatten() {
                if let Ok(status) = std::fs::read_to_string(task.path().join("status")) {
                    voluntary += status
                        .lines()
                        .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                        .map(|value| value.trim().parse::<u64>().expect("a number"))
                        .unwrap_or(0);
                }
            }
        }
        CpuSample {
            cpu_ticks: utime + stime,
            voluntary,
        }
    }
}

fn clk_tck() -> u32 {
    let output = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .expect("getconf exists");
    let text = String::from_utf8(output.stdout).expect("a number");
    text.trim().parse().expect("CLK_TCK is a number")
}

// ---------------------------------------------------------------------------
// The T-302 ack flows (§6; the fake session, isolated configs)
// ---------------------------------------------------------------------------

/// The ack record's path inside one isolated config directory.
fn ack_path(config: &std::path::Path) -> PathBuf {
    config.join("osza-netmon").join("notice-ack")
}

/// The file mode's permission bits, as stat reports them.
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("the record exists")
        .permissions()
        .mode()
        & 0o777
}

/// The record's content matches the card-fixed shape
/// (`version=<digits>` then `acknowledged=<digits>`).
fn ack_content_is_shaped(content: &str) -> bool {
    let mut lines = content.trim_end_matches('\n').split('\n');
    let Some(version) = lines.next() else {
        return false;
    };
    let Some(acknowledged) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let version_ok = version
        .strip_prefix("version=")
        .is_some_and(|digits| digits.parse::<u32>().is_ok());
    let acknowledged_ok = acknowledged
        .strip_prefix("acknowledged=")
        .is_some_and(|digits| digits.parse::<u64>().is_ok());
    version_ok && acknowledged_ok
}

fn flow_first_run_ack() -> Result<(), String> {
    // First run: no record → the notice; `y` writes the record (mode
    // 0600, the card-fixed format); the scope follows; confirming the
    // NON-suggested fake interface runs the scan there (the exact
    // device count — the PQ-3 attach decided through the real loop).
    let config = isolated_config("flow-first");
    let mut session = fake_session_in("flow-first", &config);
    // The notice is up (fake_session_in waited for it); `y`.
    session.send(b"y");
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(20)),
        "y never acknowledged the notice",
    );
    // The record: written, mode 0600, card-fixed shape.
    let record = ack_path(&config);
    let content = std::fs::read_to_string(&record)
        .map_err(|error| format!("the ack record was not written: {error}"))?;
    if mode_of(&record) != 0o600 {
        return Err(format!(
            "the ack record's mode is {:o}, expected 600",
            mode_of(&record)
        ));
    }
    if !content.starts_with("version=1\n") {
        return Err(format!("the record's version line is wrong: {content:?}"));
    }
    if !ack_content_is_shaped(&content) {
        return Err(format!("the record's shape is wrong: {content:?}"));
    }
    // Confirm the NON-suggested interface (wlan9, 198.51.100.128/25):
    // the fake fixture's row order is deterministic ([eth9, wlan9]),
    // so one `j` moves the selection to it. The exact-count assertion
    // below backstops the selection (the suggested interface's table
    // would read 4, a missing attach 1).
    session.send(b"j");
    drive_confirm_selected(&mut session)?;
    // The exact count: wlan9's own device + its one fake neighbor = 2
    // (the suggested eth9's three-host table would read 4; a missing
    // attach would read 1).
    assert_or(
        wait_for_device_count(&session, "2", Duration::from_secs(30)),
        "the confirmed interface's exact device count never appeared",
    );
    session.send(b"q");
    assert_restored(&mut session, 0)
}

fn flow_second_run() -> Result<(), String> {
    // A valid stored record: the session starts acknowledged — the
    // scope screen first, no notice.
    let config = isolated_config("flow-second");
    let dir = config.join("osza-netmon");
    std::fs::create_dir_all(&dir).expect("the config dir");
    std::fs::write(
        dir.join("notice-ack"),
        "version=1\nacknowledged=1700000000\n",
    )
    .expect("the seeded record");
    let command = format!(
        "{xdg}{self} --fake-session",
        xdg = xdg_prefix(&config),
        self = SELF_EXE.get().expect("set in main")
    );
    let mut session = PtySession::spawn("flow-second", &command, 4);
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(30)),
        "the second run never went straight to the scope screen",
    );
    if contains(&session.output(), b"Authorization") {
        return Err("the full notice showed despite the valid record".to_owned());
    }
    session.send(b"q");
    assert_restored(&mut session, 0)
}

fn flow_ack_reask() -> Result<(), String> {
    // A corrupt record, then a version-mismatched one: the full
    // notice shows again for both.
    let config = isolated_config("flow-reask");
    let dir = config.join("osza-netmon");
    std::fs::create_dir_all(&dir).expect("the config dir");
    let record = dir.join("notice-ack");
    // (a) Corrupt content.
    std::fs::write(&record, "garbage that is not a record").expect("seed");
    let mut session = fake_session_in("flow-reask-a", &config);
    session.send(b"q");
    assert_restored(&mut session, 0)?;
    // (b) A version mismatch (the text changed since the ack).
    std::fs::write(&record, "version=9\nacknowledged=1700000000\n").expect("seed");
    let mut session = fake_session_in("flow-reask-b", &config);
    session.send(b"q");
    assert_restored(&mut session, 0)?;
    Ok(())
}

fn flow_ack_write_failure() -> Result<(), String> {
    // XDG_CONFIG_HOME points at a regular file: the directories
    // cannot be created, the write fails — non-fatal (ADR-004), the
    // app continues to the scope and beyond.
    let blocker = isolated_config("flow-writefail");
    let blocker_file = blocker.join("blocker");
    std::fs::write(&blocker_file, "a file, not a directory").expect("the blocker");
    let command = format!(
        "{xdg}{self} --fake-session",
        xdg = xdg_prefix(&blocker_file),
        self = SELF_EXE.get().expect("set in main")
    );
    let mut session = PtySession::spawn("flow-writefail", &command, 4);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the notice never showed (the read path must be total)",
    );
    session.send(b"y");
    // The write failed silently: the app CONTINUES (no crash, no
    // exit) — the scope screen arrives.
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(20)),
        "the app did not continue past the failed ack write",
    );
    session.send(b"q");
    assert_restored(&mut session, 0)
}

// ---------------------------------------------------------------------------
// The PQ-3 acceptance: the two-interface netns egress proof (§5.7.6)
// ---------------------------------------------------------------------------

fn netns_two_interface_egress() -> Result<(), String> {
    if !unshare_available() {
        return Err(
            "SKIPPED: unshare --user --map-root-user --net unavailable here \
             (the fake-source flow is the fallback evidence)"
                .to_owned(),
        );
    }
    // Two veth pairs, two subnets, each peer an ARP-answered address;
    // two listeners bound to the PEER ends (veth1 sees what leaves
    // veth0; veth3 what leaves veth2). The suggested interface is
    // veth0 (both virtual-class, name order); the scenario confirms
    // veth2 — the NON-suggested one.
    //
    // The listeners are double-forked (`( cmd & )` — the subshell
    // exits immediately, the listener reparents away): they must NOT
    // remain `script(1)`'s children, or script's child handling spins
    // (it stops forwarding stdin mid-session and never exits —
    // observed on this util-linux; the double-fork sidesteps it).
    let artifacts = isolated_config("egress");
    let log1 = artifacts.join("veth1.log");
    let log3 = artifacts.join("veth3.log");
    let self_exe = SELF_EXE.get().expect("set in main");
    let setup = format!(
        "ip link add veth0 type veth peer name veth1 \
         && ip link add veth2 type veth peer name veth3 \
         && ip link set lo up \
         && ip link set veth0 up && ip addr add 198.51.100.1/24 dev veth0 \
         && ip link set veth1 up && ip addr add 198.51.100.5/24 dev veth1 \
         && ip link set veth2 up && ip addr add 203.0.113.1/24 dev veth2 \
         && ip link set veth3 up && ip addr add 203.0.113.5/24 dev veth3 \
         && ip link set veth0 addrgenmode none \
         && ip link set veth1 addrgenmode none \
         && ip link set veth2 addrgenmode none \
         && ip link set veth3 addrgenmode none \
         && {{ ( {self_exe} --arp-listener veth1 {log1} 240 & ); \
              ( {self_exe} --arp-listener veth3 {log3} 240 & ); }} \
         && sleep 1",
        log1 = log1.display(),
        log3 = log3.display(),
    );
    let config = isolated_config("egress-app");
    let command = format!("{xdg}{BIN}", xdg = xdg_prefix(&config));
    let mut session = PtySession::spawn_netns("egress", &setup, &command, 4);
    assert_or(
        session.wait_for(b"Authorization", Duration::from_secs(30)),
        "the egress session never showed the notice",
    );
    // §5.7.1 evidence: both sockets opened, capabilities dropped —
    // CapEff/CapPrm zero while the TUI runs (SR-06).
    let Some(pid) = session.app_pid() else {
        session.kill();
        return Err("the egress app's pid was not found".to_owned());
    };
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("the app is alive");
    let cap_eff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .expect("the CapEff line");
    let cap_prm = status
        .lines()
        .find_map(|line| line.strip_prefix("CapPrm:"))
        .expect("the CapPrm line");
    if cap_eff.trim() != "0000000000000000" || cap_prm.trim() != "0000000000000000" {
        return Err(format!(
            "capabilities were not dropped (CapEff {cap_eff:?}, CapPrm {cap_prm:?})"
        ));
    }
    // The listeners are up and quiet; the suggestion (veth0) is the
    // initial selection — its mode-line network renders contiguously
    // over the digit-free notice frame.
    session.send(b"y");
    assert_or(
        session.wait_for(b"Choose", Duration::from_secs(20)),
        "y never acknowledged the notice (egress)",
    );
    assert_or(
        session.wait_for(b"198.51.100.0/24", Duration::from_secs(20)),
        "the suggested interface's subnet never showed",
    );
    // Zero egress pre-confirm: both wires carry no ARP request.
    std::thread::sleep(Duration::from_millis(500));
    let quiet1 = listener_arp_requests(&log1);
    let quiet3 = listener_arp_requests(&log3);
    if !quiet1.is_empty() || !quiet3.is_empty() {
        return Err(format!(
            "ARP egress before the confirmation: veth1 {:?} veth3 {:?}",
            quiet1, quiet3
        ));
    }
    // Select veth2 (the NON-suggested interface) and confirm it: the
    // eligible rows in creation order are veth0, veth1, veth2, veth3,
    // so two `j` presses walk the selection veth0 → veth1 → veth2
    // (veth1's mode line is identical to veth0's — same /24 — so only
    // the second move shows). The fragment "113.0/24" (veth2's
    // network address in the mode line) is written as one contiguous
    // run and collides with nothing (the row shows the interface's
    // .1 address). The egress assertions below backstop the
    // selection.
    session.send(b"jj");
    // The mode line's change (198.51.100.0/24 → 203.0.113.0/24) is
    // written as cell-diff runs; which fragment stays contiguous
    // depends on the cells that happen to match, so the wait accepts
    // either candidate and only looks at bytes written after the
    // presses (the row texts contain the subnets already).
    let mark = session.output().len();
    assert_or(
        wait_for_after(
            &session,
            mark,
            &[b"113.0/24", b"3.0/24"],
            Duration::from_secs(20),
        ),
        "the selection never reached the second subnet's interface",
    );
    drive_confirm_selected_public(&mut session)?;
    // The scan: 253 targets × 2 passes at 100 pps + windows ≈ 10 s.
    // Wait for the full evidence — the request count on the confirmed
    // wire growing and then settling (stable for 3 s) — so the final
    // assertion covers the whole sweep, not its first packets.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut requests = Vec::new();
    let mut last_count = 0usize;
    let mut last_change = Instant::now();
    while Instant::now() < deadline {
        requests = listener_arp_requests(&log3);
        if requests.len() != last_count {
            last_count = requests.len();
            last_change = Instant::now();
        } else if !requests.is_empty() && last_change.elapsed() > Duration::from_secs(3) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // The app goes down first (the listeners stay alive until the
    // scenario's assertions are done — killing them mid-session can
    // confuse `script(1)`'s child handling, and the harness's
    // session-exit wait does not depend on them: they hold the
    // harness's pipes, not the pty).
    session.send(b"q");
    assert_restored(&mut session, 0)?;
    kill_listeners(&[&log1, &log3]);
    if requests.is_empty() {
        return Err("the confirmed subnet's wire never saw an ARP request".to_owned());
    }
    // Every request targets the confirmed subnet, never the own or
    // the network/broadcast address.
    for request in &requests {
        let octets: Vec<u8> = request
            .split('.')
            .map(|octet| octet.parse::<u8>().expect("an octet"))
            .collect();
        if octets[..3] != [203, 0, 113] {
            return Err(format!(
                "an ARP request left to {request} (out of the confirmed subnet)"
            ));
        }
        if octets[3] == 0 || octets[3] == 1 || octets[3] == 255 {
            return Err(format!(
                "an ARP request to the non-probe address {request} (FR-SC-05)"
            ));
        }
    }
    println!(
        "\n    egress: {} ARP requests on the confirmed wire, \
         0 on the suggested interface's wire",
        requests.len()
    );
    // THE assertion: the suggested interface's wire stays empty —
    // egress landed ONLY on the confirmed subnet.
    let leaked = listener_arp_requests(&log1);
    if !leaked.is_empty() {
        return Err(format!(
            "ARP egress on the non-confirmed interface's wire: {leaked:?} (PQ-3 violated)"
        ));
    }
    Ok(())
}

/// Kills the listeners whose logs live at the given paths (their
/// `<log>.pid` sidecar files), best effort — a missing or already-dead
/// listener is not an error (the deadline is the safety net).
fn kill_listeners(logs: &[&std::path::Path]) {
    for log in logs {
        if let Ok(text) = std::fs::read_to_string(format!("{}.pid", log.display()))
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
}

/// The ARP request target addresses logged by one listener so far.
fn listener_arp_requests(log: &std::path::Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(log) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| line.strip_prefix("et=0x0806 op=1 tip="))
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn assert_or(condition: bool, message: &str) {
    assert!(condition, "{message}");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Waits until the live device count has been nonzero at least once:
/// the count cell (row 2, column 10 — `Devices: ` is nine cells) is
/// always written behind a cursor move (the space before it never
/// changes), so the pattern is `ESC[2;10H` followed by a nonzero
/// digit.
fn wait_for_nonzero_devices(session: &PtySession, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if output_has_nonzero_devices(&session.output()) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    output_has_nonzero_devices(&session.output())
}

/// Waits until one of the needles appears in the output **after** the
/// mark (bytes written after a known point — the mark is an output
/// length captured by the caller).
fn wait_for_after(session: &PtySession, mark: usize, needles: &[&[u8]], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let output = session.output();
        let tail = output.get(mark..).unwrap_or(&output);
        if needles.iter().any(|needle| contains(tail, needle)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = session.output();
    let tail = output.get(mark..).unwrap_or(&output);
    needles.iter().any(|needle| contains(tail, needle))
}

/// Waits until the live device count reads exactly `expected`: the
/// digits after the LAST cursor-addressed write to the count cell.
fn wait_for_device_count(session: &PtySession, expected: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if last_device_count(&session.output()).is_some_and(|count| count == expected) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    last_device_count(&session.output()).is_some_and(|count| count == expected)
}

/// The digits after the last count-cell write (`ESC[2;10H` + digits),
/// when any exist.
fn last_device_count(output: &[u8]) -> Option<String> {
    let prefix = b"\x1b[2;10H";
    let mut last: Option<String> = None;
    let mut start = 0;
    while let Some(found) = output[start..]
        .windows(prefix.len())
        .position(|window| window == prefix)
    {
        let digit_at = start + found + prefix.len();
        let digits: String = output[digit_at..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .map(|byte| *byte as char)
            .collect();
        if !digits.is_empty() {
            last = Some(digits);
        }
        start = start + found + prefix.len();
        if start >= output.len() {
            break;
        }
    }
    last
}

fn output_has_nonzero_devices(output: &[u8]) -> bool {
    // The incremental write (a later count change over the
    // placeholder's own line): the digits after the count cell's
    // cursor move.
    if last_device_count(output).is_some_and(|digits| digits != "0") {
        return true;
    }
    // The full-line write (the first dashboard frame over a real
    // screen): "Devices: N" as one contiguous run.
    let needle = b"Devices: ";
    let mut start = 0;
    while let Some(found) = output[start..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let digit_at = start + found + needle.len();
        if output
            .get(digit_at)
            .is_some_and(|digit| digit.is_ascii_digit() && *digit != b'0')
        {
            return true;
        }
        start = start + found + needle.len();
        if start >= output.len() {
            break;
        }
    }
    false
}

fn unshare_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}
