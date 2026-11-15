// SPDX-License-Identifier: GPL-3.0-only

//! The notice-acknowledgment store (ADR-004/ADR-013; task T-302 §5.2)
//! — the MVP's **sole persisted state**.
//!
//! This module is the wiring-role home of the file I/O the card
//! assigns to `src/ui/` ("I/O belongs here or in the assembly, never
//! in `src/app/`"): the assembly reads the record at startup (the
//! first-run rule below) and the assembly's executor interceptor
//! writes it when the E-2a effect arrives. The render path never
//! touches this module.
//!
//! # Location and format (ADR-004, card-fixed)
//!
//! * Path: `$XDG_CONFIG_HOME/osza-netmon/notice-ack`, falling back to
//!   `~/.config/osza-netmon/notice-ack` when `XDG_CONFIG_HOME` is
//!   unset or empty; directories are created as needed. Without
//!   either variable there is no honest location: the record reads as
//!   unacknowledged and writes are skipped (non-fatal).
//! * Format, exactly two lines: `version=<NOTICE_VERSION>` then
//!   `acknowledged=<unix-seconds>` (the writer always appends the
//!   final newline; the reader accepts its absence).
//! * Mode `0600` (std's `OpenOptionsExt` on create, plus an explicit
//!   `set_permissions` so a pre-existing file with wider mode is
//!   tightened on rewrite).
//!
//! # Parsing is total (P7: the file is hostile)
//!
//! [`acknowledged_version`] accepts **only** the exact shape above:
//! the right version line, a canonical decimal timestamp (no leading
//! zeros, no sign, no spaces), exactly two lines, nothing else. Any
//! deviation — missing lines, extra lines, wrong order, wrong version,
//! garbage, oversize (> [`MAX_ACK_BYTES`]), non-UTF-8 — reads as
//! *unacknowledged*, so the full notice shows again (ADR-004's
//! first-run-or-version-change rule). Nothing here panics on any
//! input.
//!
//! # Write failures are non-fatal (ADR-004)
//!
//! "If it cannot be written, the app continues and asks again next
//! run." [`AckStore::write`] returns the error for the caller to
//! ignore (or log); nothing about the session changes.

use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::SystemTime;

/// The largest record the reader accepts: the honest format is two
/// short lines (< 60 bytes); anything larger is hostile and reads as
/// unacknowledged (SR-10's bounded reads).
pub const MAX_ACK_BYTES: usize = 4096;

/// The directory under the config root (ADR-004: `osza-netmon`).
const CONFIG_DIR: &str = "osza-netmon";
/// The record's file name (ADR-004: `notice-ack`).
const ACK_FILE: &str = "notice-ack";

/// Parses one record's content against the expected notice version
/// (pure, total; module docs for the exact shape).
///
/// `content` is the file's bytes as UTF-8 text — callers that cannot
/// decode the file pass `None`, which is unacknowledged by definition.
pub fn acknowledged_version(content: Option<&str>, expected_version: u32) -> bool {
    let Some(text) = content else {
        return false;
    };
    // One optional trailing newline; anything else after the second
    // line is a deviation.
    let body = text.strip_suffix('\n').unwrap_or(text);
    // Exactly two lines, in order.
    let Some((version_line, ack_line)) = body.split_once('\n') else {
        return false;
    };
    if ack_line.contains('\n') {
        return false;
    }
    // The version line: exactly `version=<expected>`, canonically
    // rendered (no leading zeros, no spaces).
    if version_line != format!("version={expected_version}") {
        return false;
    }
    // The timestamp line: `acknowledged=<canonical decimal u64>`.
    let Some(digits) = ack_line.strip_prefix("acknowledged=") else {
        return false;
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    // Canonical: re-rendering the parsed value must reproduce the
    // digits (rejects "007", "+7", " 7").
    match digits.parse::<u64>() {
        Ok(seconds) => digits == seconds.to_string(),
        Err(_) => false,
    }
}

/// The bounded read of one record: `None` when the file is missing,
/// unreadable, oversize or not valid UTF-8 (all unacknowledged).
fn read_content(path: &std::path::Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() as usize > MAX_ACK_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.len() > MAX_ACK_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Where the record lives (the wiring-role store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckStore {
    path: PathBuf,
}

impl AckStore {
    /// Resolves the record's location from the environment (ADR-004):
    /// `$XDG_CONFIG_HOME` when set and non-empty, else `$HOME/.config`;
    /// `None` when neither is available (no honest location — the
    /// record reads as unacknowledged and writes are skipped).
    pub fn from_env() -> Option<Self> {
        let base = match std::env::var("XDG_CONFIG_HOME") {
            Ok(value) if !value.is_empty() => PathBuf::from(value),
            _ => match std::env::var("HOME") {
                Ok(home) if !home.is_empty() => PathBuf::from(home).join(".config"),
                _ => return None,
            },
        };
        Some(AckStore {
            path: base.join(CONFIG_DIR).join(ACK_FILE),
        })
    }

    /// A store at an explicit path (the pty harness's isolated
    /// scenario directories).
    pub fn at(path: PathBuf) -> Self {
        AckStore { path }
    }

    /// The record's path (diagnostics and the tests' assertions).
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Whether the stored record acknowledges `version` (the first-run
    /// rule: missing, corrupt, hostile or version-mismatched records
    /// all read as unacknowledged — the full notice shows again).
    pub fn acknowledges(&self, version: u32) -> bool {
        let Some(content) = read_content(&self.path) else {
            return false;
        };
        acknowledged_version(Some(&content), version)
    }

    /// Writes the record: `version=<version>` and
    /// `acknowledged=<unix-seconds>`, mode `0600`, creating
    /// directories as needed. A failure is the caller's to ignore
    /// (ADR-004: non-fatal, "asks again next run").
    ///
    /// # Errors
    /// Any I/O failure verbatim (the directories could not be created,
    /// the file could not be written or tightened).
    pub fn write(&self, version: u32) -> io::Result<()> {
        let Some(parent) = self.path.parent() else {
            return Err(io::Error::other("the ack path has no parent directory"));
        };
        fs::create_dir_all(parent)?;
        let seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)?;
        writeln!(file, "version={version}")?;
        writeln!(file, "acknowledged={seconds}")?;
        file.flush()?;
        // Tighten a pre-existing file whose mode was wider than the
        // writer's own (the create-time mode only applies to fresh
        // files); a failure here is as non-fatal as any other.
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    /// Unique temp directories without external crates: the process
    /// id plus a counter, under the standard temp dir.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "osza-t302-ack-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("the temp dir is creatable");
        dir
    }

    fn write_raw(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent creatable");
        }
        fs::write(path, content).expect("raw write");
    }

    // ---- the pure parser's totality --------------------------------------

    #[test]
    fn the_parser_accepts_exactly_the_honest_shapes() {
        // The writer's own shape (final newline) and the same without
        // it — nothing else.
        assert!(acknowledged_version(
            Some("version=1\nacknowledged=42\n"),
            1
        ));
        assert!(acknowledged_version(Some("version=1\nacknowledged=42"), 1));
        assert!(acknowledged_version(Some("version=1\nacknowledged=0\n"), 1));
        // The missing file / undecodable content.
        assert!(!acknowledged_version(None, 1));
        // A different version is a mismatch by definition.
        assert!(!acknowledged_version(
            Some("version=2\nacknowledged=42\n"),
            1
        ));
        assert!(acknowledged_version(
            Some("version=2\nacknowledged=42\n"),
            2
        ));
    }

    #[test]
    fn the_parser_rejects_every_deviation() {
        let cases = [
            "",                                                         // empty
            "\n",                                                       // one blank line
            "version=1\n",                                              // missing ack line
            "acknowledged=42\nversion=1\n",                             // wrong order
            "version=1\nacknowledged=42\nextra\n",                      // extra line
            "version=1\nacknowledged=42\n\n",                           // trailing blank line
            "version=1acknowledged=42",                                 // no newline separator
            "version=1 \nacknowledged=42\n",                            // trailing space
            "version=1\nacknowledged=42 \n",                            // trailing space
            "version=1\nacknowledged=+42\n",                            // signed
            "version=1\nacknowledged=-42\n",                            // negative
            "version=1\nacknowledged=007\n",                            // leading zeros
            "version=1\nacknowledged=\n",                               // empty timestamp
            "version=1\nacknowledged=99999999999999999999999999\n",     // overflow
            "version=01\nacknowledged=42\n",                            // non-canonical version
            "version = 1\nacknowledged=42\n",                           // spaces around =
            "VERSION=1\nacknowledged=42\n",                             // case
            "version=1\nacknowledged=42\r\n", // CR (the strip only removes \n)
            "garbage",                        // not the format at all
            "version=1\nacknowledged=42\nversion=1\nacknowledged=42\n", // doubled
        ];
        for case in cases {
            assert!(
                !acknowledged_version(Some(case), 1),
                "must be rejected: {case:?}"
            );
        }
    }

    // ---- the store -------------------------------------------------------

    #[test]
    fn the_round_trip_writes_mode_0600_and_reads_back() {
        let dir = temp_dir();
        let store = AckStore::at(dir.join("nested").join("notice-ack"));
        assert!(!store.acknowledges(1), "nothing is stored yet");
        store.write(1).expect("the write succeeds");
        let mode = fs::metadata(store.path())
            .expect("the record exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the record's mode is 0600");
        assert!(store.acknowledges(1));
        // A different version does not match.
        assert!(!store.acknowledges(2));
        // A rewrite keeps the mode and updates the version.
        store.write(2).expect("the rewrite succeeds");
        assert!(store.acknowledges(2));
        assert!(!store.acknowledges(1));
        let mode = fs::metadata(store.path())
            .expect("the record exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pre_existing_wide_mode_file_is_tightened_on_rewrite() {
        let dir = temp_dir();
        let store = AckStore::at(dir.join("notice-ack"));
        write_raw(store.path(), "version=9\nacknowledged=1\n");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o666)).expect("widen");
        // The wide, wrong-version record reads as unacknowledged…
        assert!(!store.acknowledges(1));
        // …and a rewrite tightens the mode back to 0600.
        store.write(1).expect("rewrite");
        let mode = fs::metadata(store.path())
            .expect("the record exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(store.acknowledges(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostile_files_read_as_unacknowledged() {
        let dir = temp_dir();
        let store = AckStore::at(dir.join("notice-ack"));
        // Garbage, oversize, a directory in the record's place.
        write_raw(store.path(), "not a record at all");
        assert!(!store.acknowledges(1));
        write_raw(
            store.path(),
            &format!("version=1\nacknowledged=42\n{}", "x".repeat(MAX_ACK_BYTES)),
        );
        assert!(!store.acknowledges(1), "oversize is rejected");
        // Non-UTF-8 bytes.
        fs::write(store.path(), [0xff, 0xfe, 0x00, 0x01]).expect("binary");
        assert!(!store.acknowledges(1));
        // A missing file.
        let missing = AckStore::at(dir.join("missing").join("notice-ack"));
        assert!(!missing.acknowledges(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_failures_are_typed_errors_never_panics() {
        // The parent path is a regular file: directory creation fails.
        let dir = temp_dir();
        let blocker = dir.join("blocker");
        fs::write(&blocker, "a file, not a directory").expect("blocker");
        let store = AckStore::at(blocker.join("osza-netmon").join("notice-ack"));
        let result = store.write(1);
        assert!(result.is_err(), "the write must fail, not panic");
        assert!(!store.acknowledges(1));
        let _ = fs::remove_dir_all(&dir);
    }
}
