// SPDX-License-Identifier: GPL-3.0-only

//! Binary entry point for `osza-netmon` (task T-000 bootstrap).
//!
//! The binary is deliberately thin: it classifies the command-line
//! arguments and prints the version, the short usage text, or a one-line
//! error. No product behavior exists yet; later tasks wire the real
//! application here (`plan.md` §13).

use std::process::ExitCode;

use osza_netmon::{APP_NAME, ArgError, CliOutcome, DISPLAY_NAME, VERSION, classify_args};

fn main() -> ExitCode {
    match classify_args(std::env::args_os()) {
        CliOutcome::PrintVersion => {
            print_version();
            ExitCode::SUCCESS
        }
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

// The plan (§7 SR-03) denies `print_stdout`/`print_stderr` crate-wide:
// nothing that can run while the TUI is active may write to the standard
// streams. The TUI does not exist yet (T-000 adds no product behavior),
// and the three functions below are the CLI boundary, executed before
// any terminal initialization and outside any TUI lifetime. The task
// card (T-000 §5.3) permits a narrowly scoped `#[allow]` for exactly
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
