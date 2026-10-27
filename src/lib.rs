// SPDX-License-Identifier: GPL-3.0-only

//! Library crate for `osza-netmon`.
//!
//! Task T-000 (repository bootstrap) puts only the application identity
//! constants and the command-line argument classification here. Product
//! behavior arrives with the later tasks in `plan.md` §13.
//!
//! Task T-002 adds the domain model under [`model`]: the boundary-validated
//! core primitives of `plan.md` §5.2–5.3.

pub mod model;

use std::ffi::OsString;

/// Machine name of the application (binary name, CLI prefix).
///
/// Per ADR-001 this constant and [`DISPLAY_NAME`] are the only places in
/// code where the application name is spelled out; every other occurrence
/// must reference one of them.
pub const APP_NAME: &str = "osza-netmon";

/// Human-readable display name used on UI surfaces.
///
/// Per ADR-001 this is the second of the two single sources for the name.
pub const DISPLAY_NAME: &str = "osza Network Monitor";

/// Application version, resolved from the package version at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors that can occur while classifying command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    /// An argument was not valid UTF-8.
    #[error("argument is not valid UTF-8")]
    InvalidUtf8,
    /// An argument was not recognized.
    #[error("unrecognized argument: {0}")]
    Unrecognized(String),
}

/// What the program should do after classifying the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    /// Print `<APP_NAME> <VERSION>` to stdout and exit with code 0.
    PrintVersion,
    /// Print the short usage text to stdout and exit with code 0.
    PrintHelp,
    /// Print a one-line error to stderr and exit with code 2.
    Error(ArgError),
}

/// Classify the process arguments.
///
/// `args` is the full argument vector as delivered by
/// [`std::env::args_os`], including the program name in the first
/// position; that first element is ignored. An argument that is not valid
/// UTF-8 classifies as an error instead of panicking (plan §7: external
/// input is hostile and must never panic the program).
///
/// T-000 interprets exactly one argument, the first one; the full flag
/// parser arrives with task T-402. With no argument at all the outcome is
/// [`CliOutcome::PrintHelp`]: T-000 adds no product behavior, and the
/// interactive default that will start the TUI arrives with a later task.
pub fn classify_args<I>(args: I) -> CliOutcome
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut args = args.into_iter();
    // argv[0] is the program name, not an argument to interpret.
    let _program_name = args.next();
    let first: Option<OsString> = args.next().map(Into::into);
    let Some(arg) = first else {
        return CliOutcome::PrintHelp;
    };
    let Some(text) = arg.to_str() else {
        return CliOutcome::Error(ArgError::InvalidUtf8);
    };
    match text {
        "--version" | "-V" => CliOutcome::PrintVersion,
        "--help" | "-h" => CliOutcome::PrintHelp,
        other => CliOutcome::Error(ArgError::Unrecognized(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flags_are_recognized() {
        assert_eq!(
            classify_args(["osza-netmon", "--version"]),
            CliOutcome::PrintVersion
        );
        assert_eq!(
            classify_args(["osza-netmon", "-V"]),
            CliOutcome::PrintVersion
        );
    }

    #[test]
    fn help_flags_are_recognized() {
        assert_eq!(
            classify_args(["osza-netmon", "--help"]),
            CliOutcome::PrintHelp
        );
        assert_eq!(classify_args(["osza-netmon", "-h"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(classify_args(["osza-netmon"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn program_name_is_ignored_even_if_it_looks_like_a_flag() {
        // A single element is the program name, not an argument.
        assert_eq!(classify_args(["--version"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn only_the_first_argument_is_interpreted() {
        // T-000 reads exactly one argument; the full parser is T-402.
        assert_eq!(
            classify_args(["osza-netmon", "--version", "extra"]),
            CliOutcome::PrintVersion
        );
    }

    #[test]
    fn unknown_flag_is_an_error() {
        let outcome = classify_args(["osza-netmon", "--bogus"]);
        assert_eq!(
            outcome,
            CliOutcome::Error(ArgError::Unrecognized("--bogus".to_owned()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_is_an_error_not_a_panic() {
        use std::os::unix::ffi::OsStringExt;
        let argv = [
            OsString::from("osza-netmon"),
            OsString::from_vec(vec![0xff, 0xfe, 0xfd]),
        ];
        assert_eq!(
            classify_args(argv),
            CliOutcome::Error(ArgError::InvalidUtf8)
        );
    }
}
