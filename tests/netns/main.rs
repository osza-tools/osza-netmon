// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// This is a test binary (a [[test]] target, `harness = false` — see
// Cargo.toml), but cargo compiles such targets WITHOUT `--cfg test`, so
// the clippy.toml test allowances (allow-unwrap-in-tests and friends)
// do not apply and the crate-wide denies from [lints.clippy] fire on
// scenario assertions. The relief below is scoped to exactly this one
// file — the same narrowly-scoped pattern as examples/poc_discover.rs
// (task card §8) — while every production module under src/ keeps the
// full deny set.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! The T-106 network-namespace integration harness (plan §11.2; task
//! card T-106 v1.4.0) — one custom test binary.
//!
//! Why a custom binary (`harness = false` in Cargo.toml): the responder
//! and the S7 probes re-exec **this same executable** with subcommands
//! (`--responder`, `--probe`, `--measure` — task card §3, implementation
//! option (a): "self-reexec of the test binary, no new artifact"), and a
//! generated libtest main cannot dispatch subcommands. The scenario
//! runner below replaces the harness: scenarios run strictly
//! sequentially with a per-scenario watchdog (the suite can never hang,
//! task card §5.2/§8) and `--test-threads=1`-style serialization is
//! enforced by construction.
//!
//! Gating (task card §5.1):
//!
//! * without `OSZA_NETMON_TESTS=1` the suite reports every scenario as
//!   *skipped* and exits `0` — `cargo test --locked --all-features`
//!   then behaves exactly as before: no namespaces, no `ip`, no
//!   `unshare`, no failure;
//! * with the variable set but without user-namespace root, the suite
//!   fails fast with the exact remediation command;
//! * with both, the S1–S7 scenarios run; `--measure` additionally runs
//!   the S8/S9 matrix (separate entry point, no threshold assertions).
//!
//! Usage (the standard invocation — see the task card §9):
//!
//! ```text
//! unshare --user --map-root-user --net bash -c \
//!   'OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture'
//! ```
//!
//! Any arguments other than the subcommands (libtest flags such as
//! `--test-threads` or `--nocapture` passed through by cargo) are
//! accepted and ignored — serialization is the harness's own doing.

mod config;
mod frames;
mod lab;
mod measure;
mod probes;
mod responder;
mod rng;
mod rxlog;
mod scenarios;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

/// The opt-in gate (plan §11.2: the netns suites run "behind
/// OSZA_NETNS_TESTS=1").
pub const GATE: &str = "OSZA_NETMON_TESTS";

/// The per-scenario watchdog: generous (the slowest scenario, S2, needs
/// ≈10 s; setup on a cold CI runner a few more) — its job is only to
/// make a hung scenario a *failure* instead of a hung suite.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(180);

/// The scenario table (order = plan §11.2 order, after the harness's
/// own self-checks).
const SCENARIOS: &[(&str, fn())] = &[
    (
        "harness self-checks (codec/log/config round trips)",
        selfchecks,
    ),
    (
        "S1 20 mixed responders, all discovered",
        scenarios::s1_mixed_responders,
    ),
    (
        "S2 250 addresses within NFR-02",
        scenarios::s2_full_sweep_budget,
    ),
    (
        "S3 silent targets, clean completion",
        scenarios::s3_silent_targets,
    ),
    ("S4 proxy ARP, one MAC many IPs", scenarios::s4_proxy_arp),
    (
        "S5 hostile: unsolicited reply",
        scenarios::s5_hostile_unsolicited,
    ),
    (
        "S5 hostile: truncated frame",
        scenarios::s5_hostile_truncated,
    ),
    (
        "S5 hostile: multicast sender MAC",
        scenarios::s5_hostile_multicast_mac,
    ),
    (
        "S5 hostile: out-of-scope sender IP",
        scenarios::s5_hostile_out_of_scope,
    ),
    (
        "S5 hostile: flood vs the response cap",
        scenarios::s5_hostile_flood,
    ),
    (
        "S6 egress: only ARP requests to in-scope targets",
        scenarios::s6_egress_only_arp_requests,
    ),
    ("S7 privilege model (SR-06)", scenarios::s7_privilege_model),
];

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    // Subcommands must be argv[1] (the re-exec and `cargo test -- …`
    // conventions both put them there).
    if args.len() >= 2 {
        let first = args[1].to_string_lossy();
        match first.as_ref() {
            "--responder" => {
                responder::main(&args[2..]);
                return ExitCode::SUCCESS;
            }
            "--probe" => {
                return probes::main(&args[2..]);
            }
            "--measure" => {
                measure::main(&args[2..]);
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    suite_main()
}

/// `true` when the opt-in gate is set.
pub fn suite_enabled() -> bool {
    std::env::var_os(GATE).is_some_and(|value| !value.is_empty())
}

/// The fast in-process checks of the harness's own parsers and frame
/// builders (they run as the first "scenario" because this target has
/// no libtest runner — §11.4 still demands meaningful tests, and these
/// are the harness's unit layer).
fn selfchecks() {
    frames::selftests::synthetic_like_macs_are_well_formed();
    frames::selftests::reply_round_trips_through_the_production_parser();
    frames::selftests::request_parsing_rejects_non_requests_and_short_frames();
    config::selftests::config_round_trips();
    config::selftests::parse_is_total_and_fail_closed();
    config::selftests::profile_parameters_match_appendix_d();
    rxlog::selftests::parses_ready_rx_tx_drop_and_notes();
    rxlog::selftests::window_and_gap_math();
    rxlog::selftests::malformed_lines_are_counted_never_panicked();
}

/// The scenario-suite entry point (skip / fail fast / run).
fn suite_main() -> ExitCode {
    if !suite_enabled() {
        println!(
            "netns suite: skipped ({GATE} is not set; \
             set it and run inside unshare --user --map-root-user --net to enable)"
        );
        return ExitCode::SUCCESS;
    }
    ensure_environment();

    println!(
        "netns suite: {} scenario(s), serialized, watchdog {SCENARIO_TIMEOUT:?}",
        SCENARIOS.len()
    );
    let suite_started = Instant::now();
    let mut failures = 0usize;
    for (name, scenario) in SCENARIOS {
        let started = Instant::now();
        match run_with_watchdog(*scenario) {
            Ok(()) => {
                println!(
                    "scenario ok: {name} ({:.1}s)",
                    started.elapsed().as_secs_f64()
                );
            }
            Err(reason) => {
                failures += 1;
                println!(
                    "scenario FAILED: {name} ({:.1}s): {reason}",
                    started.elapsed().as_secs_f64()
                );
            }
        }
    }
    println!(
        "netns suite: {} scenario(s), {} failure(s), {:.1}s total",
        SCENARIOS.len(),
        failures,
        suite_started.elapsed().as_secs_f64()
    );
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Runs one scenario (a plain test function) in a thread, catching
/// panics, with a watchdog.
///
/// A timed-out scenario is a failure and its thread is abandoned (the
/// process exits at the end regardless — a hung lab cannot hang CI);
/// its interfaces live in the throwaway namespace, which dies with the
/// wrapper, and per-scenario interface names prevent collisions with
/// the scenarios that still run.
fn run_with_watchdog(scenario: fn()) -> Result<(), String> {
    let (sender, receiver) = std::sync::mpsc::channel::<Result<(), String>>();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(scenario));
        let _ = sender.send(match result {
            Ok(()) => Ok(()),
            Err(payload) => Err(panic_message(&payload)),
        });
    });
    match receiver.recv_timeout(SCENARIO_TIMEOUT) {
        Ok(result) => {
            let _ = worker.join();
            result
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "watchdog: the scenario exceeded {SCENARIO_TIMEOUT:?}"
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            Err("the scenario thread ended without reporting".to_owned())
        }
    }
}

/// A panic payload as a readable one-liner.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "the scenario panicked (non-string payload)".to_owned()
    }
}

/// The environment probe (task card §5.1): fails fast, once per
/// process, with the exact remediation command when the gate is set but
/// the privileges are missing.
pub fn ensure_environment() {
    static CHECK: OnceLock<Result<(), String>> = OnceLock::new();
    let outcome = CHECK.get_or_init(probe_environment);
    if let Err(problem) = outcome {
        panic!("netns suite: the environment is not usable: {problem}");
    }
}

/// The actual probe: `ip`, `unshare` and `bash` on PATH (spawnable —
/// `ip --version` exits non-zero despite printing its version, so only
/// the spawn result is checked), and user-namespace root
/// (`CAP_NET_RAW` + `CAP_NET_ADMIN` effective).
fn probe_environment() -> Result<(), String> {
    for tool in ["ip", "unshare", "bash"] {
        let probe = std::process::Command::new(tool)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Err(err) = probe {
            return Err(format!("`{tool}` is needed but could not be run: {err}"));
        }
    }
    match osza_netmon::discovery::privilege::read_thread_status() {
        Ok(status) => {
            const CAP_NET_ADMIN: u64 = 1 << 12;
            const CAP_NET_RAW: u64 = 1 << 13;
            if status.effective & CAP_NET_RAW == 0 || status.effective & CAP_NET_ADMIN == 0 {
                let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
                Err(format!(
                    "this process lacks user-namespace root (CapEff={:016x}); \
                     run the suite inside its wrapper:\n\
                     unshare --user --map-root-user --net bash -c \
                     'cd {} && {GATE}=1 cargo test --locked --all-features \
                     --test netns -- --test-threads=1 --nocapture'\n\
                     (if unprivileged user namespaces are unavailable on this host, \
                     an administrator can enable them, e.g. by relaxing \
                     kernel.apparmor_restrict_unprivileged_userns)",
                    status.effective,
                    cwd.display()
                ))
            } else {
                Ok(())
            }
        }
        Err(err) => Err(format!("reading the thread status failed: {err}")),
    }
}
