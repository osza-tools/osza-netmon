// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// This is the T-202 maintainer CLI (task card §3): a boundary tool whose
// purpose is to print statistics to stdout and diagnostics to stderr,
// like the T-104 `poc_discover.rs` precedent. The print ban of plan §7
// SR-03 targets TUI-reachable code; the T-202 task card §8 pre-approves
// exactly these two file-scoped allows here. Do not copy them anywhere
// else.
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! Maintainer CLI that converts the four public IEEE registry CSVs into
//! the committed vendor database (task T-202, policies D-1…D-9).
//!
//! Usage:
//!
//! ```text
//! gen_oui --mal <oui.csv> --mam <mam.csv> --mas <oui36.csv> \
//!         --iab <iab.csv> --date YYYY-MM-DD --out <vendor-db.bin>
//! ```
//!
//! The four inputs are the IEEE `MA-L` (24-bit), `MA-M` (28-bit),
//! `MA-S` (36-bit) and legacy `IAB` (36-bit) registry CSVs, read with
//! fields taken by header name (`Registry`, `Assignment`,
//! `Organization Name`); a UTF-8 BOM is tolerated (D-1). Malformed rows
//! are skipped and counted, never fatal. All merge policy and encoding
//! logic lives in the library (`enrichment::vendor`); this file only
//! extracts CSV rows, parses the command line, prints statistics and
//! writes the output file, so everything testable is testable without a
//! CSV file.
//!
//! `--date` is the retrieval date (UTC) of the maintainer's download
//! (D-7); it is embedded in the database header and recorded in
//! `data/oui/SOURCE.md`.
//!
//! Exit codes: `0` success, `1` data error (unreadable input, missing
//! column, encoding failure, unwritable output), `2` usage error
//! (missing or malformed arguments, including an impossible `--date`).

use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

use osza_netmon::enrichment::vendor::DatabaseDate;
use osza_netmon::enrichment::vendor::RegistryKind;
use osza_netmon::enrichment::vendor::VendorDb;
use osza_netmon::enrichment::vendor::VendorEntry;
use osza_netmon::enrichment::vendor::VendorEntryError;
use osza_netmon::enrichment::vendor::build_db_detailed;
use osza_netmon::enrichment::vendor::normalize_organization_name;

/// What the command line asks for (parsed and validated; pure, tested
/// below).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    /// Path of the MA-L (24-bit) registry CSV.
    mal: String,
    /// Path of the MA-M (28-bit) registry CSV.
    mam: String,
    /// Path of the MA-S (36-bit) registry CSV.
    mas: String,
    /// Path of the legacy IAB (36-bit) registry CSV.
    iab: String,
    /// The retrieval date (UTC) of the download (D-7).
    date: DatabaseDate,
    /// Path of the database image to write.
    out: String,
}

/// Classifies the full argv (program name in position 0).
///
/// Every flag takes exactly one value; each may be given at most once.
/// Non-UTF-8 arguments are errors, not panics (plan §7: external input
/// is hostile).
fn classify_args(argv: &[OsString]) -> Result<Args, String> {
    let mut mal: Option<String> = None;
    let mut mam: Option<String> = None;
    let mut mas: Option<String> = None;
    let mut iab: Option<String> = None;
    let mut date_text: Option<String> = None;
    let mut out: Option<String> = None;
    let mut index = 0usize;
    while let Some(arg) = argv.get(index) {
        if index == 0 {
            index += 1;
            continue; // program name
        }
        let text = arg
            .to_str()
            .ok_or_else(|| "argument is not valid UTF-8".to_owned())?;
        let slot: &mut Option<String> = match text {
            "--mal" => &mut mal,
            "--mam" => &mut mam,
            "--mas" => &mut mas,
            "--iab" => &mut iab,
            "--date" => &mut date_text,
            "--out" => &mut out,
            other => return Err(format!("unrecognized argument: {other:?}")),
        };
        if slot.is_some() {
            return Err(format!("{text} given more than once"));
        }
        let value = argv
            .get(index + 1)
            .and_then(|next| next.to_str())
            .ok_or_else(|| format!("{text} requires a value"))?;
        *slot = Some(value.to_owned());
        index += 2;
    }
    let mal = mal.ok_or_else(|| "missing required --mal <MA-L csv path>".to_owned())?;
    let mam = mam.ok_or_else(|| "missing required --mam <MA-M csv path>".to_owned())?;
    let mas = mas.ok_or_else(|| "missing required --mas <MA-S csv path>".to_owned())?;
    let iab = iab.ok_or_else(|| "missing required --iab <IAB csv path>".to_owned())?;
    let date_text = date_text.ok_or_else(|| "missing required --date <YYYY-MM-DD>".to_owned())?;
    let date = parse_date(&date_text)?;
    let out = out.ok_or_else(|| "missing required --out <database path>".to_owned())?;
    Ok(Args {
        mal,
        mam,
        mas,
        iab,
        date,
        out,
    })
}

/// Parses `YYYY-MM-DD` into a validated [`DatabaseDate`] (D-7).
fn parse_date(text: &str) -> Result<DatabaseDate, String> {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 3 {
        return Err(format!("invalid --date {text:?}: expected YYYY-MM-DD"));
    }
    let year = parts
        .first()
        .and_then(|part| part.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid --date {text:?}: the year is not a number"))?;
    let month = parts
        .get(1)
        .and_then(|part| part.parse::<u8>().ok())
        .ok_or_else(|| format!("invalid --date {text:?}: the month is not a number"))?;
    let day = parts
        .get(2)
        .and_then(|part| part.parse::<u8>().ok())
        .ok_or_else(|| format!("invalid --date {text:?}: the day is not a number"))?;
    DatabaseDate::new(year, month, day)
        .map_err(|_| format!("invalid --date {text:?}: not a real calendar date"))
}

/// Per-input extraction statistics (D-1: skipped rows are counted, never
/// fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
struct InputStats {
    /// The registry class this input was passed as.
    registry: RegistryKind,
    /// The input path as given.
    path: String,
    /// Data rows read (excluding the header).
    rows: usize,
    /// Rows that became entries.
    entries: usize,
    /// Rows skipped and counted (all reasons).
    skipped: usize,
}

/// Why rows were skipped, across all inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SkipReasons {
    /// Wrong field count or unreadable record.
    field_count: usize,
    /// `Registry` field not one of the four labels.
    registry: usize,
    /// Assignment not the right hexadecimal length.
    assignment: usize,
    /// Name empty or whitespace-only (D-5).
    empty_name: usize,
}

impl SkipReasons {
    /// Total skipped rows.
    fn total(&self) -> usize {
        self.field_count + self.registry + self.assignment + self.empty_name
    }
}

/// Everything `print_stats` needs.
struct RunOutcome {
    per_input: Vec<InputStats>,
    reasons: SkipReasons,
    /// The database as loaded back from the freshly written image
    /// (proves the file parses).
    loaded: VendorDb,
    /// Output path as given.
    out: String,
    /// Image size in bytes.
    byte_size: usize,
    /// D-3 duplicate resolutions.
    dropped_duplicates: usize,
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let args = match classify_args(&argv) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: gen_oui --mal <oui.csv> --mam <mam.csv> --mas <oui36.csv> \
                 --iab <iab.csv> --date YYYY-MM-DD --out <vendor-db.bin>"
            );
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(outcome) => {
            print_stats(&args, &outcome);
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("gen_oui: {message}");
            ExitCode::from(1)
        }
    }
}

/// Reads the four inputs (D-1/D-2), builds the database and writes it.
fn run(args: &Args) -> Result<RunOutcome, String> {
    let inputs = [
        (RegistryKind::MaL, &args.mal),
        (RegistryKind::MaM, &args.mam),
        (RegistryKind::MaS, &args.mas),
        (RegistryKind::Iab, &args.iab),
    ];
    // D-2 merge order: MA-L, then MA-M, then MA-S, then IAB — the order
    // the entries are pushed in here.
    let mut entries: Vec<VendorEntry> = Vec::new();
    let mut per_input: Vec<InputStats> = Vec::with_capacity(inputs.len());
    let mut reasons = SkipReasons::default();
    for (registry, path) in inputs {
        let stats = read_csv(registry, path, &mut entries, &mut reasons)?;
        per_input.push(stats);
    }
    let built = build_db_detailed(&entries, args.date)
        .map_err(|error| format!("building the database failed: {error}"))?;
    fs::write(&args.out, &built.bytes)
        .map_err(|error| format!("writing {} failed: {error}", args.out))?;
    // Load the image we just wrote: the printed totals describe what the
    // runtime will actually serve, and a failure here is a data error.
    let loaded = VendorDb::from_bytes(&built.bytes)
        .map_err(|error| format!("re-loading the built image failed: {error}"))?;
    let dropped_duplicates = built.stats.dropped_duplicates.len();
    Ok(RunOutcome {
        per_input,
        reasons,
        loaded,
        out: args.out.clone(),
        byte_size: built.bytes.len(),
        dropped_duplicates,
    })
}

/// Extracts one registry CSV (D-1): fields by header name, BOM tolerated,
/// malformed rows skipped and counted.
fn read_csv(
    registry: RegistryKind,
    path: &str,
    entries: &mut Vec<VendorEntry>,
    reasons: &mut SkipReasons,
) -> Result<InputStats, String> {
    let raw = fs::read(path).map_err(|error| format!("reading {path} failed: {error}"))?;
    let stripped = strip_bom(&raw);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(stripped);
    let headers = reader
        .headers()
        .map_err(|error| format!("{path}: reading the CSV header failed: {error}"))?;
    let registry_column =
        column(headers, "Registry").ok_or_else(|| format!("{path}: no 'Registry' column"))?;
    let assignment_column =
        column(headers, "Assignment").ok_or_else(|| format!("{path}: no 'Assignment' column"))?;
    let name_column = column(headers, "Organization Name")
        .ok_or_else(|| format!("{path}: no 'Organization Name' column"))?;

    let mut rows = 0usize;
    let mut count = 0usize;
    let mut skipped = 0usize;
    for record in reader.records() {
        rows += 1;
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                // D-1: wrong field count or broken quoting — counted.
                reasons.field_count += 1;
                skipped += 1;
                continue;
            }
        };
        let label = record.get(registry_column);
        let kind = label.and_then(RegistryKind::from_csv_label);
        let Some(kind) = kind else {
            reasons.registry += 1;
            skipped += 1;
            continue;
        };
        let assignment = record.get(assignment_column);
        let raw_name = record.get(name_column);
        let (assignment, raw_name) = match (assignment, raw_name) {
            (Some(assignment), Some(raw_name)) => (assignment, raw_name),
            _ => {
                reasons.field_count += 1;
                skipped += 1;
                continue;
            }
        };
        // D-4: entity unescape happens before the boundary.
        let name = normalize_organization_name(raw_name);
        match VendorEntry::new(kind, assignment, &name) {
            Ok(entry) => {
                entries.push(entry);
                count += 1;
            }
            Err(VendorEntryError::EmptyName) => {
                // D-5: empty/whitespace-only — counted.
                reasons.empty_name += 1;
                skipped += 1;
            }
            Err(_) => {
                reasons.assignment += 1;
                skipped += 1;
            }
        }
    }
    Ok(InputStats {
        registry,
        path: path.to_owned(),
        rows,
        entries: count,
        skipped,
    })
}

/// Strips a UTF-8 BOM if present (D-1).
fn strip_bom(bytes: &[u8]) -> &[u8] {
    match bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        Some(rest) => rest,
        None => bytes,
    }
}

/// Index of `name` in the header record, if present.
fn column(headers: &csv::StringRecord, name: &str) -> Option<usize> {
    (0..headers.len()).find(|&index| headers.get(index) == Some(name))
}

/// Prints the ready-to-paste markdown statistics block (task card R-7).
fn print_stats(args: &Args, outcome: &RunOutcome) {
    println!("## gen_oui statistics");
    println!();
    println!("| Registry | Input | Rows | Entries | Skipped rows |");
    println!("| --- | --- | ---: | ---: | ---: |");
    for stats in &outcome.per_input {
        println!(
            "| {} | {} | {} | {} | {} |",
            stats.registry, stats.path, stats.rows, stats.entries, stats.skipped
        );
    }
    let reasons = &outcome.reasons;
    println!();
    println!(
        "Skipped rows by reason: field count {} · registry {} · assignment {} · empty name {}",
        reasons.field_count, reasons.registry, reasons.assignment, reasons.empty_name
    );
    println!(
        "Total entries: {} (skipped rows total: {})",
        outcome
            .per_input
            .iter()
            .map(|stats| stats.entries)
            .sum::<usize>(),
        reasons.total()
    );
    println!("Database date: {date}", date = args.date);
    let counts = outcome.loaded.registry_counts();
    println!(
        "Usable entries after load-time sanitization (D-6): {} (MA-L {} · MA-M {} · MA-S {} · IAB {}) · skipped at load: {}",
        outcome.loaded.entry_count(),
        counts.ma_l,
        counts.ma_m,
        counts.ma_s,
        counts.iab,
        outcome.loaded.skipped_entries()
    );
    println!(
        "Dropped duplicates (D-3, last row wins): {}",
        outcome.dropped_duplicates
    );
    println!("Output: {} ({} bytes)", outcome.out, outcome.byte_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("gen_oui"))
            .chain(items.iter().map(OsString::from))
            .collect()
    }

    #[test]
    fn all_flags_with_values_parse() {
        let args = classify_args(&argv(&[
            "--mal",
            "oui.csv",
            "--mam",
            "mam.csv",
            "--mas",
            "oui36.csv",
            "--iab",
            "iab.csv",
            "--date",
            "2026-11-03",
            "--out",
            "vendor-db.bin",
        ]))
        .expect("full argument set must parse");
        assert_eq!(args.mal, "oui.csv");
        assert_eq!(args.mam, "mam.csv");
        assert_eq!(args.mas, "oui36.csv");
        assert_eq!(args.iab, "iab.csv");
        assert_eq!(args.out, "vendor-db.bin");
        assert_eq!(args.date.to_string(), "2026-11-03");
    }

    #[test]
    fn flags_parse_in_any_order() {
        let args = classify_args(&argv(&[
            "--out",
            "out.bin",
            "--date",
            "2024-02-29",
            "--iab",
            "i.csv",
            "--mas",
            "s.csv",
            "--mam",
            "m.csv",
            "--mal",
            "l.csv",
        ]))
        .expect("order must not matter");
        assert_eq!(args.mal, "l.csv");
        assert_eq!(args.date.to_string(), "2024-02-29");
    }

    #[test]
    fn missing_required_flag_is_a_usage_error() {
        let error = classify_args(&argv(&["--mal", "oui.csv"])).unwrap_err();
        assert!(error.contains("--mam"), "error: {error}");
        let error = classify_args(&argv(&[])).unwrap_err();
        assert!(error.contains("--mal"), "error: {error}");
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        let error = classify_args(&argv(&["--verbose"])).unwrap_err();
        assert!(error.contains("unrecognized"), "error: {error}");
    }

    #[test]
    fn duplicate_flag_is_a_usage_error() {
        let error = classify_args(&argv(&["--mal", "a.csv", "--mal", "b.csv"])).unwrap_err();
        assert!(error.contains("more than once"), "error: {error}");
    }

    #[test]
    fn flag_without_value_is_a_usage_error() {
        let error = classify_args(&argv(&["--mal"])).unwrap_err();
        assert!(error.contains("requires a value"), "error: {error}");
    }

    #[test]
    fn malformed_dates_are_usage_errors() {
        let full = |date: &str| {
            argv(&[
                "--mal", "l.csv", "--mam", "m.csv", "--mas", "s.csv", "--iab", "i.csv", "--out",
                "o.bin", "--date", date,
            ])
        };
        for bad in [
            "2026-13-01",
            "2026-00-10",
            "2023-02-29",
            "2026-11-32",
            "20261103",
            "x",
        ] {
            let error = classify_args(&full(bad)).unwrap_err();
            assert!(error.contains("--date"), "input {bad:?}, error: {error}");
        }
    }

    #[test]
    fn valid_leap_day_is_accepted() {
        let date = parse_date("2024-02-29").expect("2024 is a leap year");
        assert_eq!(date.to_string(), "2024-02-29");
    }

    #[test]
    fn bom_is_stripped_only_when_present() {
        assert_eq!(strip_bom(&[0xEF, 0xBB, 0xBF, b'a']), b"a".as_slice());
        assert_eq!(strip_bom(b"abc"), b"abc".as_slice());
        assert_eq!(strip_bom(&[]), b"".as_slice());
        // A BOM look-alike is left verbatim.
        assert_eq!(strip_bom(&[0xEF, 0xBB, 0x00]), &[0xEF, 0xBB, 0x00]);
    }
}
