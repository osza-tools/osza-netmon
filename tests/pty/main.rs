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

//! The T-301 pty integration harness (task §6): the acceptance
//! evidence for the terminal lifecycle, driven through real ptys.
//!
//! The harness is a custom test binary (`harness = false`, the netns
//! target's own precedent) for two reasons: its
//! [`--fake-session`](fakes()) mode re-execs this executable as the
//! fake-source application under `script(1)`, which a generated
//! libtest main cannot dispatch; and the scenarios are sequential by
//! nature (each drives a process for seconds).
//!
//! # Scenarios
//!
//! 1. `restore_normal_q` — (a) of §6: `q` exits 0 with the terminal
//!    restored (raw mode off via the echo probe, capture off via the
//!    stream, alternate screen left).
//! 2. `restore_error_exit` — (b): the fault seam's error arm exits 1
//!    restored.
//! 3. `restore_panic` — (c): the fault seam's panic arm exits 101
//!    restored (ratatui's hook + the earlier hook + the guards).
//! 4. `restore_sigterm` / 5. `restore_sighup` — (d)/(e): the signal
//!    thread quits through the app's normal quit path: exit 0,
//!    restored.
//! 6. `resize_too_small_toggle` — 80×24 → 79×24 → 80×24: the
//!    too-small placeholder appears and recovers, the dashboard
//!    state never resets (run on the fake session: a deterministic
//!    confirmable interface).
//! 7. `smoke_fake_source` — the end-to-end smoke over the reviewed
//!    fakes (the T-205 AC-5 variant under the pty): notice → `y` →
//!    scope → `Enter` → a nonzero live device count → `q` → exit 0.
//! 8. `smoke_netns_real` — the same smoke against the real binary in
//!    a network namespace with a veth pair (§14.3.7: synthetic
//!    networks only; skipped with a note when `unshare` is
//!    unavailable).
//! 9. `idle_cpu` — NFR-04: the real binary idle at the notice screen;
//!    utime+stime from `/proc/<pid>/stat` as a percentage of one
//!    core (60 s locally, 10 s under `CI`, `OSZA_PTY_IDLE_SECS`
//!    override — the card's documented variant), plus the
//!    voluntary-context-switch rate (wake-ups only for timers/input).

mod drive;
mod fakes;

use std::panic::AssertUnwindSafe;
use std::process::Command;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use drive::PtySession;

/// The real binary under test (cargo sets this for the test target).
const BIN: &str = env!("CARGO_BIN_EXE_osza-netmon");

/// This harness's own path, resolved once (the `--fake-session`
/// scenarios re-exec it under `script`).
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
    // The fake session re-execs this same executable; resolve the
    // path once (arg0 is unreliable).
    let self_exe = std::env::current_exe()
        .expect("current_exe works")
        .to_string_lossy()
        .into_owned();
    let _ = SELF_EXE.set(self_exe);

    /// One scenario: a name and its zero-argument runner.
    type Scenario = (&'static str, fn() -> Result<(), String>);

    let scenarios: [Scenario; 9] = [
        ("restore_normal_q", restore_normal_q),
        ("restore_error_exit", restore_error_exit),
        ("restore_panic", restore_panic),
        ("restore_sigterm", restore_sigterm),
        ("restore_sighup", restore_sighup),
        ("resize_too_small_toggle", resize_too_small_toggle),
        ("smoke_fake_source", smoke_fake_source),
        ("smoke_netns_real", smoke_netns_real),
        ("idle_cpu", idle_cpu),
    ];

    let started = Instant::now();
    let mut failures = 0usize;
    for (name, scenario) in scenarios {
        print!("pty scenario {name:<24} … ");
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
// The five restore scenarios (§6 a–e)
// ---------------------------------------------------------------------------

// Sentinel note: ratatui renders by cell diff — a word is written as
// one contiguous run, but the *space* between words matches the blank
// buffer and is skipped, so multi-word literals never appear
// contiguous in the stream. All sentinels are therefore single words
// (unique per screen), and the device count is matched by its
// cursor-addressed write (`ESC[2;10H` + digits — the count cell is
// always reached by a move: the space before it never changes).

/// Spawns the real binary on a fresh pty and waits for the first
/// (notice) frame.
fn real_app(label: &str, tail: u64) -> PtySession {
    let session = PtySession::spawn(label, BIN, tail);
    assert_or(
        session.wait_for(b"Notice", Duration::from_secs(30)),
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
// The resize scenario (§6)
// ---------------------------------------------------------------------------

fn resize_too_small_toggle() -> Result<(), String> {
    // On the fake session: a deterministic confirmable interface, so
    // the dashboard is guaranteed after Enter regardless of the
    // runner's interfaces.
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

/// Spawns this harness in `--fake-session` mode on a fresh pty.
fn fake_session(label: &str) -> PtySession {
    let command = format!("{} --fake-session", SELF_EXE.get().expect("set in main"));
    let session = PtySession::spawn(label, &command, 4);
    assert_or(
        session.wait_for(b"Notice", Duration::from_secs(30)),
        "the fake session never showed the notice",
    );
    session
}

/// notice → `y` → scope → `Enter` → dashboard (the shared prefix of
/// the smoke and resize scenarios).
fn drive_flow_to_dashboard(session: &mut PtySession) -> Result<(), String> {
    session.send(b"y");
    assert_or(
        session.wait_for(b"Scope", Duration::from_secs(20)),
        "y never acknowledged the notice",
    );
    session.send(b"\r");
    assert_or(
        session.wait_for(b"Dashboard", Duration::from_secs(20)),
        "Enter never confirmed the scope",
    );
    Ok(())
}

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
    let setup = "ip link add veth0 type veth peer name veth1 \
                 && ip link set lo up \
                 && ip link set veth0 up \
                 && ip addr add 192.0.2.1/24 dev veth0 \
                 && ip link set veth1 up \
                 && ip addr add 192.0.2.5/24 dev veth1";
    let mut session = PtySession::spawn_netns("smoke-netns", setup, BIN, 4);
    assert_or(
        session.wait_for(b"Notice", Duration::from_secs(30)),
        "the netns session never showed the notice",
    );
    session.send(b"y");
    assert_or(
        session.wait_for(b"Scope", Duration::from_secs(20)),
        "y never acknowledged the notice (netns)",
    );
    session.send(b"\r");
    assert_or(
        session.wait_for(b"Dashboard", Duration::from_secs(20)),
        "Enter never confirmed the scope (netns)",
    );
    // The real sweep: two passes over 254 addresses plus the listen
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
    let mut session = PtySession::spawn("idle", BIN, 1);
    assert_or(
        session.wait_for(b"Notice", Duration::from_secs(30)),
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
// Shared helpers
// ---------------------------------------------------------------------------

fn assert_or(condition: bool, message: &str) {
    assert!(condition, "{message}");
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

fn output_has_nonzero_devices(output: &[u8]) -> bool {
    let prefix = b"\x1b[2;10H";
    let mut start = 0;
    while let Some(found) = output[start..]
        .windows(prefix.len())
        .position(|window| window == prefix)
    {
        let digit_at = start + found + prefix.len();
        if output
            .get(digit_at)
            .is_some_and(|digit| digit.is_ascii_digit() && *digit != b'0')
        {
            return true;
        }
        start = start + found + prefix.len();
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
