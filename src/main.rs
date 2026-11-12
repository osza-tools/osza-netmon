// SPDX-License-Identifier: GPL-3.0-only

//! Binary entry point for `osza-netmon`.
//!
//! Thin wiring (plan §8.1): the command-line classification of the
//! bootstrap task, and — since T-301 — the interactive default: with
//! no arguments the assembled application runs on the real terminal
//! lifecycle (§8.8), everything else stays the T-000 behavior
//! (`--version`, `--help`, the argument error). No business logic
//! lives here; the assembly owns the wiring and its parameters.
//!
//! The `print_*` helpers are the CLI boundary, executed before any
//! terminal initialization and outside any TUI lifetime; the
//! post-restore error report of [`run_app`](self::run_app) is the
//! one place the standard streams are touched after the TUI existed
//! (AGENTS.md: pre-init/post-restore only).

use std::process::ExitCode;

use osza_netmon::{APP_NAME, ArgError, CliOutcome, DISPLAY_NAME, VERSION, classify_args};

fn main() -> ExitCode {
    // The interactive default (T-301): no argument at all runs the
    // TUI — `classify_args` cannot express this yet (its no-argument
    // answer is `PrintHelp` from the T-000 era; the full parser is
    // T-402's), so the raw argument count distinguishes the two
    // `PrintHelp` cases here, at the wiring layer where it belongs.
    let bare_invocation = std::env::args_os().count() == 1;
    match classify_args(std::env::args_os()) {
        CliOutcome::PrintVersion => {
            print_version();
            ExitCode::SUCCESS
        }
        CliOutcome::PrintHelp if bare_invocation => run_app(),
        CliOutcome::PrintHelp => {
            print_usage();
            ExitCode::SUCCESS
        }
        CliOutcome::Error(err) => {
            print_error(&err);
            ExitCode::from(2)
        }
    }
}

/// Runs the assembled application with the default parameters (§5.2:
/// thin wiring — the assembly accepts parameters, parses nothing).
/// A normal quit exits 0; any failure has already restored the
/// terminal (the assembly's teardown runs on every path) and is
/// reported once, here, post-restore.
fn run_app() -> ExitCode {
    match osza_netmon::ui::assembly::run(osza_netmon::ui::assembly::AssemblyParams::default()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_app_error(&error);
            ExitCode::FAILURE
        }
    }
}

// The plan (§7 SR-03) denies `print_stdout`/`print_stderr` crate-wide:
// nothing that can run while the TUI is active may write to the standard
// streams. The four functions below are the CLI boundary, executed
// before any terminal initialization and outside any TUI lifetime
// (report_app_error runs strictly post-restore). The task card
// (T-000 §5.3) established a narrowly scoped `#[allow]` for exactly
// these two lints in exactly this file. Do not copy these allows
// anywhere else.

#[allow(clippy::print_stdout)]
fn print_version() {
    println!("{APP_NAME} {VERSION}");
}

#[allow(clippy::print_stdout)]
fn print_usage() {
    println!("{DISPLAY_NAME} {VERSION} (pre-release)");
    println!();
    println!("Usage: {APP_NAME} [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -V, --version  Print version information and exit");
    println!("  -h, --help     Print this help text and exit");
}

#[allow(clippy::print_stderr)]
fn print_error(err: &ArgError) {
    eprintln!("{APP_NAME}: {err}");
}

/// The post-restore application error report: exactly one line, after
/// the assembly restored the terminal (§8.7: `main` may talk to the
/// streams pre-init and post-restore — this is the latter).
#[allow(clippy::print_stderr)]
fn report_app_error(error: &osza_netmon::ui::assembly::AssemblyError) {
    eprintln!("{APP_NAME}: {error}");
}
