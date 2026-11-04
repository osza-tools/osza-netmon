// SPDX-License-Identifier: GPL-3.0-only

//! Vendor-name lookup backed by an embedded, IEEE-OUI-derived
//! database (plan §6.5 FR-EN-01/FR-EN-02, task T-202).
//!
//! The database is built ahead of time by the maintainer CLI
//! `examples/gen_oui.rs` from the four public IEEE registry CSVs — MA-L
//! (24-bit prefixes), MA-M (28-bit), MA-S (36-bit) and the legacy IAB
//! (36-bit) — applying the T-202 task-card data policies D-1…D-9 (merge
//! order, duplicate resolution, entity unescaping, name skipping,
//! determinism). The resulting image is committed as
//! `data/oui/vendor-db.bin` next to its provenance record
//! `data/oui/SOURCE.md` (FR-EN-02), and this module embeds it with
//! `include_bytes!`: the lookup never touches the network or the
//! filesystem at runtime.
//!
//! Lookup (FR-EN-01): a locally-administered MAC answers
//! [`VendorLookup::PrivateAddress`] before any table is consulted;
//! otherwise the 36-bit, 28-bit and 24-bit tables are searched in that
//! order — longest prefix first — and the first hit wins. A miss at all
//! three lengths answers [`VendorLookup::Unknown`].
//!
//! Every stored name crosses the model boundary at load time (FR-EN-04,
//! task-card policy D-6): [`VendorDb::from_bytes`] runs each name through
//! `DisplayText::try_from`, so the names a lookup returns are already
//! sanitized (whitespace collapsed, control/bidi/zero-width characters
//! removed, truncated to 64 characters). An entry whose name sanitizes to
//! empty is skipped and counted, and its prefix then simply misses.
//!
//! The loader is a total parser (plan §7 SR-02): any input — including
//! every kind of corrupt image — yields `Ok` or a typed
//! [`VendorDbError`], never a panic.
//!
//! # Intended T-205 wiring (plan §5.1/§5.3; recorded here for the app task)
//!
//! * [`VendorLookup::Found`] → `Field::Known { value: name, source:
//!   `Source::VendorDb` }` (stored via `Registry::set_vendor`).
//! * [`VendorLookup::PrivateAddress`] → the plan §5.3 `Private address`
//!   label in the Vendor column — a label, not a database answer; the
//!   vendor field itself stays `Field::Unknown`.
//! * [`VendorLookup::Unknown`] → `Field::Unknown`.
//!
//! # Database image format (version 1)
//!
//! All integers are little-endian. The image is
//! `header | table24 | table28 | table36 | names`, laid out contiguously
//! with no padding between regions:
//!
//! ```text
//! header (52 bytes)
//!   [ 0.. 6]  magic = b"OZOUDB"
//!   [ 6.. 8]  format version (u16) = 1
//!   [ 8..10]  date_year (u16)
//!   [10]      date_month (u8)
//!   [11]      date_day (u8)
//!   [12..16]  count_mal (u32)   stored MA-L entries (post D-3/D-5)
//!   [16..20]  count_mam (u32)   stored MA-M entries
//!   [20..24]  count_mas (u32)   stored MA-S entries
//!   [24..28]  count_iab (u32)   stored IAB entries
//!   [28..32]  off_table24 (u32) = 52
//!   [32..36]  off_table28 (u32) = off_table24 + count_mal * 12
//!   [36..40]  off_table36 (u32) = off_table28 + count_mam * 12
//!   [40..44]  off_names   (u32) = off_table36 + (count_mas + count_iab) * 16
//!   [44..48]  names_len   (u32) = total_len - off_names
//!   [48..52]  total_len   (u32) = byte length of the whole image
//!
//! table24: count_mal entries of 12 bytes, ascending by key:
//!   [0..4] key (u32, < 2^24)  [4] registry tag (u8 = 1)
//!   [5..9] name_off (u32)     [9..11] name_len (u16)   [11] reserved (u8 = 0)
//! table28: count_mam entries of 12 bytes, ascending by key:
//!   same layout, key < 2^28, registry tag = 2
//! table36: count_mas + count_iab entries of 16 bytes, ascending by key:
//!   [0..8] key (u64, < 2^36)  [8] registry tag (u8 = 3 MA-S / 4 IAB)
//!   [9..13] name_off (u32)    [13..15] name_len (u16)  [15] reserved (u8 = 0)
//! names: names_len bytes of concatenated UTF-8 organization names,
//!   deduplicated; name_off/name_len address this region and must fall on
//!   character boundaries inside it.
//! ```
//!
//! The layout is fully determined by the header counts, so the loader
//! validates every offset against them before allocating anything;
//! `total_len` is recorded explicitly so truncation is detectable. The
//! same `(entries, date)` input always encodes to byte-identical output
//! (D-8): there are no timestamps, and the name region is written in
//! first-appearance order of the sorted tables, so no hash-map iteration
//! order can reach the output.

use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fmt;

use crate::model::{DisplayText, MacAddr};

/// Magic bytes of a vendor database image.
const MAGIC: [u8; 6] = *b"OZOUDB";
/// Database image format version produced and accepted by this module.
const FORMAT_VERSION: u16 = 1;
/// Header length of the image format, in bytes (see the module docs).
const HEADER_LEN: usize = 52;
/// Bytes per entry in the 24-bit (MA-L) table.
const ENTRY24_LEN: usize = 12;
/// Bytes per entry in the 28-bit (MA-M) table.
const ENTRY28_LEN: usize = 12;
/// Bytes per entry in the 36-bit (MA-S + IAB) table.
const ENTRY36_LEN: usize = 16;
/// Registry tag stored in table entries: MA-L.
const TAG_MAL: u8 = 1;
/// Registry tag stored in table entries: MA-M.
const TAG_MAM: u8 = 2;
/// Registry tag stored in table entries: MA-S.
const TAG_MAS: u8 = 3;
/// Registry tag stored in table entries: IAB.
const TAG_IAB: u8 = 4;

/// One of the four public IEEE registries the database is built from
/// (task-card policy D-1).
///
/// The kind determines the prefix length class — 24, 28 or 36 bits — and
/// therefore the assignment digit count and the table the entry lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryKind {
    /// MA-L: 24-bit prefixes, 6 hex digits per assignment.
    MaL,
    /// MA-M: 28-bit prefixes, 7 hex digits per assignment.
    MaM,
    /// MA-S: 36-bit prefixes, 9 hex digits per assignment.
    MaS,
    /// Legacy IAB: 36-bit prefixes, 9 hex digits per assignment.
    Iab,
}

impl RegistryKind {
    /// Maps the `Registry` CSV field value to the registry kind.
    ///
    /// Anything other than the four labels `MA-L`, `MA-M`, `MA-S`, `IAB`
    /// is not a registry this database knows (D-1: such rows are skipped
    /// and counted by the CLI).
    pub fn from_csv_label(label: &str) -> Option<Self> {
        match label {
            "MA-L" => Some(RegistryKind::MaL),
            "MA-M" => Some(RegistryKind::MaM),
            "MA-S" => Some(RegistryKind::MaS),
            "IAB" => Some(RegistryKind::Iab),
            _ => None,
        }
    }

    /// The `Registry` CSV field value of this kind.
    pub const fn label(self) -> &'static str {
        match self {
            RegistryKind::MaL => "MA-L",
            RegistryKind::MaM => "MA-M",
            RegistryKind::MaS => "MA-S",
            RegistryKind::Iab => "IAB",
        }
    }

    /// The prefix length class: 24, 28 or 36 bits.
    pub const fn bits(self) -> u8 {
        match self {
            RegistryKind::MaL => 24,
            RegistryKind::MaM => 28,
            RegistryKind::MaS | RegistryKind::Iab => 36,
        }
    }

    /// The number of hexadecimal digits in an assignment of this kind.
    const fn digits(self) -> usize {
        match self {
            RegistryKind::MaL => 6,
            RegistryKind::MaM => 7,
            RegistryKind::MaS | RegistryKind::Iab => 9,
        }
    }

    /// The registry tag byte stored in table entries.
    const fn tag(self) -> u8 {
        match self {
            RegistryKind::MaL => TAG_MAL,
            RegistryKind::MaM => TAG_MAM,
            RegistryKind::MaS => TAG_MAS,
            RegistryKind::Iab => TAG_IAB,
        }
    }

    /// Maps a registry tag byte back to the kind, if it is valid.
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TAG_MAL => Some(RegistryKind::MaL),
            TAG_MAM => Some(RegistryKind::MaM),
            TAG_MAS => Some(RegistryKind::MaS),
            TAG_IAB => Some(RegistryKind::Iab),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Errors returned when a [`VendorEntry`] is rejected at the boundary.
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VendorEntryError {
    /// The assignment is not the right number of hexadecimal digits for
    /// the registry class.
    #[error("assignment {assignment:?} is not {digits} hexadecimal digits (registry {registry})")]
    InvalidAssignment {
        /// The registry class that was expected to match.
        registry: RegistryKind,
        /// The rejected assignment text.
        assignment: String,
        /// The digit count the registry class requires.
        digits: u8,
    },
    /// The organization name is empty or whitespace-only (D-5).
    #[error("organization name is empty or whitespace-only")]
    EmptyName,
}

/// One validated input row of the builder: a registry assignment and its
/// organization name (task-card requirement R-4).
///
/// `new` is the validating boundary: the assignment must be exactly the
/// registry's digit count of hexadecimal digits (case-insensitive), and
/// the name must not be empty or whitespace-only (D-5). The name is
/// stored as given — entity unescaping (D-4) happens in
/// [`normalize_organization_name`] before the row reaches `new`, and
/// load-time sanitization (D-6) happens in [`VendorDb::from_bytes`];
/// the database keeps the full name, not a pre-truncated one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorEntry {
    registry: RegistryKind,
    key: u64,
    name: String,
}

impl VendorEntry {
    /// Validates and builds one entry from `(registry, assignment, name)`.
    pub fn new(
        registry: RegistryKind,
        assignment: &str,
        name: &str,
    ) -> Result<Self, VendorEntryError> {
        let digits = registry.digits();
        let valid =
            assignment.len() == digits && assignment.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid {
            return Err(VendorEntryError::InvalidAssignment {
                registry,
                assignment: assignment.to_owned(),
                digits: digits as u8,
            });
        }
        // Unreachable after the digit check; mapped all the same so the
        // boundary stays total.
        let key = u64::from_str_radix(assignment, 16).map_err(|_| {
            VendorEntryError::InvalidAssignment {
                registry,
                assignment: assignment.to_owned(),
                digits: digits as u8,
            }
        })?;
        if name.trim().is_empty() {
            return Err(VendorEntryError::EmptyName);
        }
        Ok(Self {
            registry,
            key,
            name: name.to_owned(),
        })
    }

    /// The registry class of the assignment.
    pub fn registry(&self) -> RegistryKind {
        self.registry
    }

    /// The assignment as uppercase hexadecimal with the registry's digit
    /// count (the IEEE `Assignment` field form).
    pub fn assignment(&self) -> String {
        format!("{:0width$X}", self.key, width = self.registry.digits())
    }

    /// The full (D-4-unescaped, not yet sanitized) organization name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Normalizes an IEEE organization name per D-4: a single left-to-right
/// pass replacing exactly the five HTML entities `&amp;` `&lt;` `&gt;`
/// `&quot;` `&apos;` by their characters.
///
/// The pass is single: `&amp;gt;` becomes `&gt;`, not `>`. Everything
/// else — case, spacing, non-ASCII letters — is kept verbatim; there is
/// no trimming and no case folding.
pub fn normalize_organization_name(raw: &str) -> String {
    const ENTITIES: [(&str, &str); 5] = [
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
    ];
    let mut out = String::with_capacity(raw.len());
    let mut index = 0usize;
    while index < raw.len() {
        let rest = &raw[index..];
        let mut matched = false;
        for (entity, replacement) in ENTITIES {
            if rest.starts_with(entity) {
                out.push_str(replacement);
                index += entity.len();
                matched = true;
                break;
            }
        }
        if !matched {
            // Copy one character (a whole UTF-8 sequence): `index` only
            // ever advances by ASCII entity lengths or character lengths,
            // so it always sits on a character boundary.
            if let Some(character) = rest.chars().next() {
                out.push(character);
                index += character.len_utf8();
            } else {
                break;
            }
        }
    }
    out
}

/// The database's retrieval date (FR-EN-02, task-card policy D-7).
///
/// `Display` is the `YYYY-MM-DD` form the help screen shows. Construction
/// via [`DatabaseDate::new`] validates a real calendar (including leap
/// years); the fields are public so callers can read them, and every
/// internal consumer re-validates (the builder and the loader do).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseDate {
    /// Calendar year (Common Era numbering).
    pub year: u16,
    /// Month of the year, 1–12.
    pub month: u8,
    /// Day of the month, valid for the month.
    pub day: u8,
}

impl DatabaseDate {
    /// Validates the calendar date and builds it.
    ///
    /// Month must be 1–12 and the day valid for that month in that year
    /// (February honors the Gregorian leap-year rule: divisible by 4, and
    /// by 400 if by 100).
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, VendorDbError> {
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap_year(year) => 29,
            2 => 28,
            _ => return Err(VendorDbError::InvalidDate { year, month, day }),
        };
        if !(1..=max_day).contains(&day) {
            return Err(VendorDbError::InvalidDate { year, month, day });
        }
        Ok(Self { year, month, day })
    }
}

impl fmt::Display for DatabaseDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Gregorian leap-year rule for [`DatabaseDate`].
fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Per-registry counts of usable (post-sanitization) entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistryCounts {
    /// MA-L (24-bit) entries.
    pub ma_l: usize,
    /// MA-M (28-bit) entries.
    pub ma_m: usize,
    /// MA-S (36-bit) entries.
    pub ma_s: usize,
    /// Legacy IAB (36-bit) entries.
    pub iab: usize,
}

/// The answer of a vendor lookup (FR-EN-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorLookup {
    /// The vendor was found; the name has already passed `DisplayText`
    /// sanitization at load time (FR-EN-04).
    Found {
        /// The sanitized organization name.
        name: DisplayText,
    },
    /// The MAC is locally-administered: no lookup is performed at all.
    PrivateAddress,
    /// The MAC is globally-administered but no prefix matched.
    Unknown,
}

/// Errors returned by the database loader and builder.
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VendorDbError {
    /// The image is shorter than its own header (or than the total length
    /// it declares).
    #[error("vendor database is truncated: {found} bytes, at least {expected} required")]
    Truncated {
        /// Bytes actually present.
        found: usize,
        /// Bytes the image needs.
        expected: usize,
    },
    /// The magic bytes do not identify a vendor database image.
    #[error("vendor database magic mismatch")]
    BadMagic,
    /// The image's format version is not one this loader accepts.
    #[error("unsupported vendor database format version {found}")]
    UnsupportedVersion {
        /// The version field of the rejected image.
        found: u16,
    },
    /// The embedded database date is not a real calendar date.
    #[error("invalid vendor database date {year}-{month:02}-{day:02}")]
    InvalidDate {
        /// Year field of the rejected date.
        year: u16,
        /// Month field of the rejected date.
        month: u8,
        /// Day field of the rejected date.
        day: u8,
    },
    /// The header's structural fields contradict each other or the image
    /// length.
    #[error("vendor database layout is inconsistent: {fault}")]
    Layout {
        /// Which structural invariant failed.
        fault: &'static str,
    },
    /// A table entry carries a registry tag that is not one of the four.
    #[error("vendor database registry tag {found} is invalid")]
    InvalidRegistryTag {
        /// The rejected tag byte.
        found: u8,
    },
    /// A table entry's key does not fit its table's prefix length.
    #[error("vendor database key 0x{found:X} exceeds its {bits}-bit table")]
    InvalidKey {
        /// The out-of-range key.
        found: u64,
        /// The table's prefix length in bits.
        bits: u8,
    },
    /// A table is not strictly ascending by key.
    #[error("vendor database table is not sorted by prefix")]
    Unsorted,
    /// The per-registry counts in the header do not match the table
    /// contents.
    #[error("vendor database per-registry counts do not match the table contents")]
    CountMismatch,
    /// A name's offset and length do not address the name region.
    #[error("vendor database name range {offset}+{len} is outside the name region")]
    NameRange {
        /// Byte offset of the name within the name region.
        offset: u32,
        /// Byte length of the name.
        len: u16,
    },
    /// The name region is not valid UTF-8.
    #[error("vendor database name region is not valid UTF-8")]
    InvalidUtf8,
    /// The image (or a name in it) exceeds a field width of the format.
    #[error("vendor database exceeds a format field limit (4 GiB image or 65,535-byte name)")]
    TooLarge,
}

/// One loaded table row: the prefix key and its sanitized name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    /// The prefix value, right-aligned (below `2^bits` for its table).
    key: u64,
    /// The sanitized organization name (D-6, FR-EN-04).
    name: DisplayText,
}

/// The parsed, in-memory vendor database (plan FR-EN-01/FR-EN-02).
///
/// Construct it from the embedded image ([`VendorDb::embedded`]) or from
/// any byte slice ([`VendorDb::from_bytes`]); both are total. The three
/// tables are held sorted by prefix, so each lookup tier is a binary
/// search.
#[derive(Debug, Clone, PartialEq)]
pub struct VendorDb {
    date: DatabaseDate,
    skipped: usize,
    counts: RegistryCounts,
    table24: Vec<Row>,
    table28: Vec<Row>,
    table36: Vec<Row>,
}

impl VendorDb {
    /// Parses a database image (total: any input yields `Ok` or `Err`,
    /// never a panic).
    ///
    /// Every structural field is validated against the layout invariants
    /// documented at the module level before any allocation is sized from
    /// the (untrusted) header counts; then each name is run through
    /// `DisplayText::try_from` (D-6): entries whose name sanitizes to
    /// empty are skipped and counted, and their prefixes then miss.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VendorDbError> {
        let found = bytes.len();
        if found < HEADER_LEN {
            return Err(VendorDbError::Truncated {
                found,
                expected: HEADER_LEN,
            });
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(VendorDbError::BadMagic);
        }
        let truncated = || VendorDbError::Truncated {
            found,
            expected: HEADER_LEN,
        };
        let version = le_u16(bytes, 6).ok_or_else(truncated)?;
        if version != FORMAT_VERSION {
            return Err(VendorDbError::UnsupportedVersion { found: version });
        }
        let year = le_u16(bytes, 8).ok_or_else(truncated)?;
        let month = byte_at(bytes, 10).ok_or_else(truncated)?;
        let day = byte_at(bytes, 11).ok_or_else(truncated)?;
        let date = DatabaseDate::new(year, month, day)?;
        let count_mal = le_u32(bytes, 12).ok_or_else(truncated)?;
        let count_mam = le_u32(bytes, 16).ok_or_else(truncated)?;
        let count_mas = le_u32(bytes, 20).ok_or_else(truncated)?;
        let count_iab = le_u32(bytes, 24).ok_or_else(truncated)?;
        let off_table24 = le_u32(bytes, 28).ok_or_else(truncated)?;
        let off_table28 = le_u32(bytes, 32).ok_or_else(truncated)?;
        let off_table36 = le_u32(bytes, 36).ok_or_else(truncated)?;
        let off_names = le_u32(bytes, 40).ok_or_else(truncated)?;
        let names_len = le_u32(bytes, 44).ok_or_else(truncated)?;
        let total_len = le_u32(bytes, 48).ok_or_else(truncated)?;

        // Layout validation in u64 arithmetic (no overflow on any input).
        let n24 = u64::from(count_mal);
        let n28 = u64::from(count_mam);
        let n36 = u64::from(count_mas)
            .checked_add(u64::from(count_iab))
            .ok_or(VendorDbError::Layout {
                fault: "registry counts overflow",
            })?;
        let exp_off28 = HEADER_LEN as u64 + n24 * ENTRY24_LEN as u64;
        let exp_off36 = exp_off28 + n28 * ENTRY28_LEN as u64;
        let exp_off_names = exp_off36 + n36 * ENTRY36_LEN as u64;
        let total64 = u64::from(total_len);
        if total64 != found as u64 {
            if total64 > found as u64 {
                return Err(VendorDbError::Truncated {
                    found,
                    expected: total_len as usize,
                });
            }
            return Err(VendorDbError::Layout {
                fault: "declared total length does not match the input length",
            });
        }
        if u64::from(off_table24) != HEADER_LEN as u64
            || u64::from(off_table28) != exp_off28
            || u64::from(off_table36) != exp_off36
            || u64::from(off_names) != exp_off_names
        {
            return Err(VendorDbError::Layout {
                fault: "table offsets are not contiguous with the header",
            });
        }
        let exp_names_len = total64
            .checked_sub(exp_off_names)
            .ok_or(VendorDbError::Layout {
                fault: "tables extend past the end of the image",
            })?;
        if u64::from(names_len) != exp_names_len {
            return Err(VendorDbError::Layout {
                fault: "name region length is inconsistent",
            });
        }

        // One UTF-8 validation covers every name; per-entry slices below
        // use `str::get`, which additionally rejects non-boundary cuts.
        let names_bytes = bytes
            .get(off_names as usize..)
            .ok_or(VendorDbError::Layout {
                fault: "name region offset is outside the image",
            })?;
        let names = std::str::from_utf8(names_bytes).map_err(|_| VendorDbError::InvalidUtf8)?;

        // The counts are now bounded by the image length (each table fits
        // exactly between its validated offsets), so sizing allocations
        // from them cannot over-allocate on hostile input.
        let mut table24: Vec<Row> = Vec::with_capacity(count_mal as usize);
        let mut table28: Vec<Row> = Vec::with_capacity(count_mam as usize);
        let mut table36: Vec<Row> = Vec::with_capacity(n36 as usize);
        let mut skipped = 0usize;
        let mut seen_mas = 0usize;
        let mut seen_iab = 0usize;
        let mut usable_mas = 0usize;
        let mut usable_iab = 0usize;

        let mut previous24: Option<u64> = None;
        for index in 0..count_mal as usize {
            let base = off_table24 as usize + index * ENTRY24_LEN;
            let entry = bytes
                .get(base..base + ENTRY24_LEN)
                .ok_or(VendorDbError::Layout {
                    fault: "table entry is outside the image",
                })?;
            if entry.get(ENTRY24_LEN - 1).copied() != Some(0) {
                return Err(VendorDbError::Layout {
                    fault: "reserved byte is set",
                });
            }
            let (key, tag, name_off, name_len) =
                parse_entry12(entry).ok_or(VendorDbError::Layout {
                    fault: "table entry is incomplete",
                })?;
            if tag != TAG_MAL {
                return Err(VendorDbError::InvalidRegistryTag { found: tag });
            }
            if key >= 1 << 24 {
                return Err(VendorDbError::InvalidKey {
                    found: key,
                    bits: 24,
                });
            }
            if previous24.is_some_and(|previous| key <= previous) {
                return Err(VendorDbError::Unsorted);
            }
            previous24 = Some(key);
            let name = slice_name(names, name_off, name_len)?;
            // D-6: DisplayText rejects only empty-after-sanitization; any
            // rejection skips the entry and counts it.
            match DisplayText::try_from(name) {
                Ok(sanitized) => table24.push(Row {
                    key,
                    name: sanitized,
                }),
                Err(_) => skipped += 1,
            }
        }

        let mut previous28: Option<u64> = None;
        for index in 0..count_mam as usize {
            let base = off_table28 as usize + index * ENTRY28_LEN;
            let entry = bytes
                .get(base..base + ENTRY28_LEN)
                .ok_or(VendorDbError::Layout {
                    fault: "table entry is outside the image",
                })?;
            if entry.get(ENTRY28_LEN - 1).copied() != Some(0) {
                return Err(VendorDbError::Layout {
                    fault: "reserved byte is set",
                });
            }
            let (key, tag, name_off, name_len) =
                parse_entry12(entry).ok_or(VendorDbError::Layout {
                    fault: "table entry is incomplete",
                })?;
            if tag != TAG_MAM {
                return Err(VendorDbError::InvalidRegistryTag { found: tag });
            }
            if key >= 1 << 28 {
                return Err(VendorDbError::InvalidKey {
                    found: key,
                    bits: 28,
                });
            }
            if previous28.is_some_and(|previous| key <= previous) {
                return Err(VendorDbError::Unsorted);
            }
            previous28 = Some(key);
            let name = slice_name(names, name_off, name_len)?;
            match DisplayText::try_from(name) {
                Ok(sanitized) => table28.push(Row {
                    key,
                    name: sanitized,
                }),
                Err(_) => skipped += 1,
            }
        }

        let mut previous36: Option<u64> = None;
        for index in 0..n36 as usize {
            let base = off_table36 as usize + index * ENTRY36_LEN;
            let entry = bytes
                .get(base..base + ENTRY36_LEN)
                .ok_or(VendorDbError::Layout {
                    fault: "table entry is outside the image",
                })?;
            if entry.get(ENTRY36_LEN - 1).copied() != Some(0) {
                return Err(VendorDbError::Layout {
                    fault: "reserved byte is set",
                });
            }
            let (key, tag, name_off, name_len) =
                parse_entry16(entry).ok_or(VendorDbError::Layout {
                    fault: "table entry is incomplete",
                })?;
            let registry = RegistryKind::from_tag(tag)
                .ok_or(VendorDbError::InvalidRegistryTag { found: tag })?;
            if key >= 1 << 36 {
                return Err(VendorDbError::InvalidKey {
                    found: key,
                    bits: 36,
                });
            }
            if previous36.is_some_and(|previous| key <= previous) {
                return Err(VendorDbError::Unsorted);
            }
            previous36 = Some(key);
            if registry == RegistryKind::Iab {
                seen_iab += 1;
            } else {
                seen_mas += 1;
            }
            let name = slice_name(names, name_off, name_len)?;
            match DisplayText::try_from(name) {
                Ok(sanitized) => {
                    if registry == RegistryKind::Iab {
                        usable_iab += 1;
                    } else {
                        usable_mas += 1;
                    }
                    table36.push(Row {
                        key,
                        name: sanitized,
                    });
                }
                Err(_) => skipped += 1,
            }
        }
        // The 24/28-bit tables admit only their own tag, so their census
        // equals the loop count by construction; the 36-bit table mixes
        // MA-S and IAB, so the split is checked against the header.
        if seen_mas != count_mas as usize || seen_iab != count_iab as usize {
            return Err(VendorDbError::CountMismatch);
        }

        Ok(Self {
            date,
            skipped,
            counts: RegistryCounts {
                ma_l: table24.len(),
                ma_m: table28.len(),
                ma_s: usable_mas,
                iab: usable_iab,
            },
            table24,
            table28,
            table36,
        })
    }

    /// The committed database, embedded at compile time (a missing file
    /// is a compile error, not a runtime one).
    pub fn embedded() -> Result<Self, VendorDbError> {
        Self::from_bytes(include_bytes!("../../data/oui/vendor-db.bin").as_slice())
    }

    /// FR-EN-01 lookup.
    ///
    /// A locally-administered MAC answers [`VendorLookup::PrivateAddress`]
    /// before any table is consulted; otherwise the 36-bit, 28-bit and
    /// 24-bit tables are searched in that order (longest prefix first)
    /// and the first hit wins; no hit → [`VendorLookup::Unknown`].
    pub fn lookup(&self, mac: &MacAddr) -> VendorLookup {
        if mac.is_locally_administered() {
            return VendorLookup::PrivateAddress;
        }
        let [a, b, c, d, e, f] = mac.octets();
        let value = u64::from(a) << 40
            | u64::from(b) << 32
            | u64::from(c) << 24
            | u64::from(d) << 16
            | u64::from(e) << 8
            | u64::from(f);
        if let Some(row) = find_row(&self.table36, value >> 12) {
            return VendorLookup::Found {
                name: row.name.clone(),
            };
        }
        if let Some(row) = find_row(&self.table28, value >> 20) {
            return VendorLookup::Found {
                name: row.name.clone(),
            };
        }
        if let Some(row) = find_row(&self.table24, value >> 24) {
            return VendorLookup::Found {
                name: row.name.clone(),
            };
        }
        VendorLookup::Unknown
    }

    /// The retrieval date recorded at build time (FR-EN-02).
    pub fn database_date(&self) -> DatabaseDate {
        self.date
    }

    /// The number of usable entries after load-time sanitization (D-6).
    pub fn entry_count(&self) -> usize {
        self.table24.len() + self.table28.len() + self.table36.len()
    }

    /// Entries skipped at load because the name sanitized to empty
    /// (expected 0 for the committed database).
    pub fn skipped_entries(&self) -> usize {
        self.skipped
    }

    /// Per-registry counts of usable entries.
    pub fn registry_counts(&self) -> RegistryCounts {
        self.counts
    }
}

/// Binary search one tier for `key`; the tables are sorted and unique by
/// construction (validated at load).
fn find_row(table: &[Row], key: u64) -> Option<&Row> {
    table
        .binary_search_by_key(&key, |row| row.key)
        .ok()
        .and_then(|index| table.get(index))
}

/// One D-3 duplicate resolution, as reported by the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedDuplicate {
    /// The registry class of the duplicated prefix.
    pub registry: RegistryKind,
    /// The duplicated assignment (uppercase hexadecimal).
    pub assignment: String,
    /// The name that won — the last row in merge order (D-3).
    pub kept: String,
    /// The names that lost, in merge order.
    pub dropped: Vec<String>,
}

/// What the merge policies dropped while building (D-3/D-5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildStats {
    /// Duplicate prefixes resolved per D-3 (same prefix AND same length
    /// class; the last row in merge order wins).
    pub dropped_duplicates: Vec<DroppedDuplicate>,
    /// Entries skipped because the name was empty or whitespace-only
    /// (D-5; 0 for entries built through [`VendorEntry::new`]).
    pub skipped_empty_names: usize,
}

/// The encoded image together with its build statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltDb {
    /// The deterministic database image (D-8).
    pub bytes: Vec<u8>,
    /// What the merge policies dropped.
    pub stats: BuildStats,
}

/// Merges the entries per D-2/D-3/D-5 and encodes the database image
/// (deterministic: identical input → byte-identical output, D-8).
///
/// `entries` must be in merge order — MA-L rows, then MA-M, MA-S, IAB
/// (the order `gen_oui` pushes them in); "last row wins" for D-3 refers
/// to that order. The date is revalidated (public fields could bypass
/// [`DatabaseDate::new`]).
pub fn build_db_detailed(
    entries: &[VendorEntry],
    date: DatabaseDate,
) -> Result<BuiltDb, VendorDbError> {
    let date = DatabaseDate::new(date.year, date.month, date.day)?;

    // D-3 dedup keyed by (length class, prefix): a later row replaces an
    // earlier one and its name is recorded as dropped. The BTreeMap keys
    // keep each length class sorted by prefix; the HashMap below is only
    // ever probed, never iterated, so no hash order reaches the output.
    let mut kept: BTreeMap<(u8, u64), VendorEntry> = BTreeMap::new();
    let mut dropped_names: BTreeMap<(u8, u64), Vec<String>> = BTreeMap::new();
    let mut skipped_empty_names = 0usize;
    for entry in entries {
        if entry.name.trim().is_empty() {
            // D-5 defensive skip (VendorEntry::new already rejects these).
            skipped_empty_names += 1;
            continue;
        }
        let key = (entry.registry.bits(), entry.key);
        if let Some(previous) = kept.insert(key, entry.clone()) {
            dropped_names.entry(key).or_default().push(previous.name);
        }
    }

    // Per-length tables, ascending by prefix (BTreeMap iteration order).
    let table24: Vec<&VendorEntry> = kept
        .values()
        .filter(|entry| entry.registry.bits() == 24)
        .collect();
    let table28: Vec<&VendorEntry> = kept
        .values()
        .filter(|entry| entry.registry.bits() == 28)
        .collect();
    let table36: Vec<&VendorEntry> = kept
        .values()
        .filter(|entry| entry.registry.bits() == 36)
        .collect();

    // Name region: deduplicated strings in first-appearance order of the
    // sorted tables (table24, then table28, then table36).
    let mut names_region: Vec<u8> = Vec::new();
    let mut name_index: HashMap<&str, (u32, u16)> = HashMap::new();
    let mut encoded24: Vec<(u64, u32, u16)> = Vec::with_capacity(table24.len());
    let mut encoded28: Vec<(u64, u32, u16)> = Vec::with_capacity(table28.len());
    let mut encoded36: Vec<(u64, u8, u32, u16)> = Vec::with_capacity(table36.len());
    for entry in &table24 {
        let (offset, len) = intern_name(&mut names_region, &mut name_index, entry.name())?;
        encoded24.push((entry.key, offset, len));
    }
    for entry in &table28 {
        let (offset, len) = intern_name(&mut names_region, &mut name_index, entry.name())?;
        encoded28.push((entry.key, offset, len));
    }
    for entry in &table36 {
        let (offset, len) = intern_name(&mut names_region, &mut name_index, entry.name())?;
        encoded36.push((entry.key, entry.registry.tag(), offset, len));
    }

    let count_mal = u32::try_from(table24.len()).map_err(|_| VendorDbError::TooLarge)?;
    let count_mam = u32::try_from(table28.len()).map_err(|_| VendorDbError::TooLarge)?;
    let count_mas = u32::try_from(
        encoded36
            .iter()
            .filter(|(_, tag, _, _)| *tag == TAG_MAS)
            .count(),
    )
    .map_err(|_| VendorDbError::TooLarge)?;
    let count_iab = u32::try_from(
        encoded36
            .iter()
            .filter(|(_, tag, _, _)| *tag == TAG_IAB)
            .count(),
    )
    .map_err(|_| VendorDbError::TooLarge)?;

    // Offset arithmetic with overflow discipline (unreachable for any
    // input that fits in memory, but total all the same).
    let table_end = |start: usize, count: usize, entry_len: usize| -> Option<usize> {
        start.checked_add(count.checked_mul(entry_len)?)
    };
    let off_table24 = HEADER_LEN;
    let off_table28 =
        table_end(off_table24, table24.len(), ENTRY24_LEN).ok_or(VendorDbError::TooLarge)?;
    let off_table36 =
        table_end(off_table28, table28.len(), ENTRY28_LEN).ok_or(VendorDbError::TooLarge)?;
    let off_names =
        table_end(off_table36, table36.len(), ENTRY36_LEN).ok_or(VendorDbError::TooLarge)?;
    let total_len = off_names
        .checked_add(names_region.len())
        .ok_or(VendorDbError::TooLarge)?;
    let names_len = u32::try_from(names_region.len()).map_err(|_| VendorDbError::TooLarge)?;
    let total = u32::try_from(total_len).map_err(|_| VendorDbError::TooLarge)?;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(MAGIC.as_slice());
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&date.year.to_le_bytes());
    out.push(date.month);
    out.push(date.day);
    out.extend_from_slice(&count_mal.to_le_bytes());
    out.extend_from_slice(&count_mam.to_le_bytes());
    out.extend_from_slice(&count_mas.to_le_bytes());
    out.extend_from_slice(&count_iab.to_le_bytes());
    out.extend_from_slice(&(off_table24 as u32).to_le_bytes());
    out.extend_from_slice(&(off_table28 as u32).to_le_bytes());
    out.extend_from_slice(&(off_table36 as u32).to_le_bytes());
    out.extend_from_slice(&(off_names as u32).to_le_bytes());
    out.extend_from_slice(&names_len.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    for (key, offset, len) in encoded24 {
        out.extend_from_slice(&(key as u32).to_le_bytes());
        out.push(TAG_MAL);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.push(0);
    }
    for (key, offset, len) in encoded28 {
        out.extend_from_slice(&(key as u32).to_le_bytes());
        out.push(TAG_MAM);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.push(0);
    }
    for (key, tag, offset, len) in encoded36 {
        out.extend_from_slice(&key.to_le_bytes());
        out.push(tag);
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.push(0);
    }
    out.extend_from_slice(&names_region);

    // D-3 report, in (length class, prefix) order for determinism.
    let mut dropped_duplicates = Vec::with_capacity(dropped_names.len());
    for (key, names) in dropped_names {
        // The winning entry for every recorded duplicate exists by
        // construction; the guard keeps this branch total anyway.
        if let Some(entry) = kept.get(&key) {
            dropped_duplicates.push(DroppedDuplicate {
                registry: entry.registry,
                assignment: entry.assignment(),
                kept: entry.name.clone(),
                dropped: names.clone(),
            });
        }
    }

    Ok(BuiltDb {
        bytes: out,
        stats: BuildStats {
            dropped_duplicates,
            skipped_empty_names,
        },
    })
}

/// Merges and encodes the database, discarding the build statistics.
pub fn build_db(entries: &[VendorEntry], date: DatabaseDate) -> Result<Vec<u8>, VendorDbError> {
    Ok(build_db_detailed(entries, date)?.bytes)
}

/// Appends `name` to the region once and returns its `(offset, length)`.
fn intern_name<'a>(
    names_region: &mut Vec<u8>,
    name_index: &mut HashMap<&'a str, (u32, u16)>,
    name: &'a str,
) -> Result<(u32, u16), VendorDbError> {
    if let Some(&hit) = name_index.get(name) {
        return Ok(hit);
    }
    let len = name.len();
    if len > usize::from(u16::MAX) {
        return Err(VendorDbError::TooLarge);
    }
    let offset = names_region.len();
    names_region.extend_from_slice(name.as_bytes());
    let pair = (offset as u32, len as u16);
    name_index.insert(name, pair);
    Ok(pair)
}

/// Little-endian `u16` at `offset`, if fully inside `bytes`.
fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice: &[u8] = bytes.get(offset..offset + 2)?;
    let array: [u8; 2] = slice.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

/// Little-endian `u32` at `offset`, if fully inside `bytes`.
fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(offset..offset + 4)?;
    let array: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

/// The byte at `offset`, if inside `bytes`.
fn byte_at(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

/// Parses one 12-byte table entry:
/// key `u32` [0..4], tag [4], name offset `u32` [5..9], name length
/// `u16` [9..11] (the trailing reserved byte is checked separately).
fn parse_entry12(entry: &[u8]) -> Option<(u64, u8, u32, u16)> {
    let key_slice: &[u8] = entry.get(0..4)?;
    let key_bytes: [u8; 4] = key_slice.try_into().ok()?;
    let key = u32::from_le_bytes(key_bytes);
    let tag = byte_at(entry, 4)?;
    let offset = le_u32(entry, 5)?;
    let len = le_u16(entry, 9)?;
    Some((u64::from(key), tag, offset, len))
}

/// Parses one 16-byte table entry:
/// key `u64` [0..8], tag [8], name offset `u32` [9..13], name length
/// `u16` [13..15] (the trailing reserved byte is checked separately).
fn parse_entry16(entry: &[u8]) -> Option<(u64, u8, u32, u16)> {
    let key_slice: &[u8] = entry.get(0..8)?;
    let key_bytes: [u8; 8] = key_slice.try_into().ok()?;
    let key = u64::from_le_bytes(key_bytes);
    let tag = byte_at(entry, 8)?;
    let offset = le_u32(entry, 9)?;
    let len = le_u16(entry, 13)?;
    Some((key, tag, offset, len))
}

/// Slices one name out of the name region (total: range and character
/// boundaries are both checked).
fn slice_name(names: &str, offset: u32, len: u16) -> Result<&str, VendorDbError> {
    let start = offset as usize;
    let end = start
        .checked_add(usize::from(len))
        .ok_or(VendorDbError::NameRange { offset, len })?;
    names
        .get(start..end)
        .ok_or(VendorDbError::NameRange { offset, len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DISPLAY_TEXT_MAX_CHARS;
    use crate::model::testing::Lcg;

    // ---- helpers ----------------------------------------------------------

    /// The synthetic database date (D-7 form).
    fn date() -> DatabaseDate {
        DatabaseDate::new(2026, 11, 3).expect("2026-11-03 is a real date")
    }

    /// Builds one valid entry or panics with a label (test-only helper).
    fn entry(registry: RegistryKind, assignment: &str, name: &str) -> VendorEntry {
        VendorEntry::new(registry, assignment, name).expect("valid synthetic entry")
    }

    /// Encodes synthetic entries with the synthetic date.
    fn build(entries: &[VendorEntry]) -> Vec<u8> {
        build_db(entries, date()).expect("synthetic entries always encode")
    }

    /// Loads a synthetic image.
    fn load(bytes: &[u8]) -> VendorDb {
        VendorDb::from_bytes(bytes).expect("synthetic images always load")
    }

    /// The MAC `key << (48-bits) | low` — callers pick keys whose first
    /// octet clears the multicast and locally-administered bits, so the
    /// address is a valid global unicast sender MAC.
    fn mac_under(key: u64, bits: u8, low: u64) -> MacAddr {
        let shift = 48 - u32::from(bits);
        let value = (key << shift) | (low & ((1u64 << shift) - 1));
        let octets = [
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        MacAddr::from_octets(octets).expect("valid sender MAC by construction")
    }

    /// A random sender MAC: the multicast bit cleared, the
    /// locally-administered bit left random (so both lookup branches are
    /// exercised), never all-zero and never broadcast.
    fn random_mac(rng: &mut Lcg) -> MacAddr {
        let value = (rng.next_u64() & 0xFFFF_FFFF_FFFF & !0x0100_0000_0000) | 1;
        let octets = [
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        MacAddr::from_octets(octets).expect("valid sender MAC by construction")
    }

    /// The name carried by a `Found` answer (or a panic naming the answer).
    fn found_name(lookup: VendorLookup) -> String {
        match lookup {
            VendorLookup::Found { name } => name.to_string(),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// A copy of `image` with `with` written at `at`.
    fn patched(image: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
        let mut out = image.to_vec();
        out.splice(at..at + with.len(), with.iter().copied());
        out
    }

    /// One entry per registry class, with distinct prefixes (first
    /// octets clear the multicast and locally-administered bits).
    fn synthetic_all_four() -> Vec<VendorEntry> {
        vec![
            entry(RegistryKind::MaL, "A8BBCC", "Alpha Twenty Four"),
            entry(RegistryKind::MaM, "A8BBCC5", "Beta Twenty Eight"),
            entry(RegistryKind::MaS, "402233AFA", "Gamma Thirty Six"),
            entry(RegistryKind::Iab, "40D8550D7", "Delta Iab"),
        ]
    }

    // ---- round trip (R-9) --------------------------------------------------

    #[test]
    fn round_trip_entries_across_all_four_registries() {
        let db = load(&build(&synthetic_all_four()));
        assert_eq!(db.database_date().to_string(), "2026-11-03");
        assert_eq!(db.entry_count(), 4);
        assert_eq!(db.skipped_entries(), 0);
        assert_eq!(
            db.registry_counts(),
            RegistryCounts {
                ma_l: 1,
                ma_m: 1,
                ma_s: 1,
                iab: 1
            }
        );
        assert_eq!(
            found_name(db.lookup(&mac_under(0xA8BBCC, 24, 0x010203))),
            "Alpha Twenty Four"
        );
        assert_eq!(
            found_name(db.lookup(&mac_under(0xA8BBCC5, 28, 0x0102))),
            "Beta Twenty Eight"
        );
        assert_eq!(
            found_name(db.lookup(&mac_under(0x402233AFA, 36, 0x01))),
            "Gamma Thirty Six"
        );
        assert_eq!(
            found_name(db.lookup(&mac_under(0x40D8550D7, 36, 0x01))),
            "Delta Iab"
        );
    }

    // ---- longest prefix (FR-EN-01, R-9) ------------------------------------

    #[test]
    fn longest_prefix_wins_and_falls_back_level_by_level() {
        let entries = [
            entry(RegistryKind::MaL, "282233", "Twenty Four Ltd"),
            entry(RegistryKind::MaM, "2822337", "Twenty Eight Ltd"),
            entry(RegistryKind::MaS, "2822337AF", "Thirty Six Ltd"),
        ];
        let db = load(&build(&entries));
        // 28:22:33:7a:f1:02 — top 36 bits = 2822337AF: the MA-S entry.
        let thirty_six: MacAddr = "28:22:33:7a:f1:02".parse().expect("valid MAC");
        assert_eq!(found_name(db.lookup(&thirty_six)), "Thirty Six Ltd");
        // 28:22:33:7b:00:01 — no 36-bit entry (2822337B0); the 28-bit
        // entry 2822337 covers the 7th hex digit 7.
        let twenty_eight: MacAddr = "28:22:33:7b:00:01".parse().expect("valid MAC");
        assert_eq!(found_name(db.lookup(&twenty_eight)), "Twenty Eight Ltd");
        // 28:22:33:4a:00:01 — neither 36- nor 28-bit match; the 24-bit
        // parent answers.
        let twenty_four: MacAddr = "28:22:33:4a:00:01".parse().expect("valid MAC");
        assert_eq!(found_name(db.lookup(&twenty_four)), "Twenty Four Ltd");
    }

    // ---- locally-administered and unknown (FR-EN-01, R-9) ------------------

    #[test]
    fn locally_administered_macs_never_touch_the_tables() {
        // The table CONTAINS the 02AABB prefix; the locally-administered
        // bit must still win before any lookup.
        let entries = [entry(RegistryKind::MaL, "02AABB", "Localbit Corp")];
        let db = load(&build(&entries));
        let mac: MacAddr = "02:aa:bb:00:00:01".parse().expect("valid MAC");
        assert!(mac.is_locally_administered());
        assert_eq!(db.lookup(&mac), VendorLookup::PrivateAddress);

        // And against an empty table.
        let empty = load(&build(&[]));
        assert_eq!(db_entry_count(&empty), 0);
        assert_eq!(empty.lookup(&mac), VendorLookup::PrivateAddress);
    }

    /// `entry_count` through the public API (helper keeps assertions short).
    fn db_entry_count(db: &VendorDb) -> usize {
        db.entry_count()
    }

    #[test]
    fn unknown_prefix_yields_unknown() {
        let db = load(&build(&synthetic_all_four()));
        let mac: MacAddr = "ec:ec:ec:11:22:33".parse().expect("valid MAC");
        assert_eq!(db.lookup(&mac), VendorLookup::Unknown);
    }

    // ---- D-3 duplicate prefixes ---------------------------------------------

    #[test]
    fn duplicate_prefixes_resolve_to_the_last_row() {
        // The two duplicate groups of the real data, reproduced
        // synthetically in file/merge order.
        let entries = [
            entry(RegistryKind::MaL, "080030", "NETWORK RESEARCH CORPORATION"),
            entry(RegistryKind::MaL, "080030", "ROYAL MELBOURNE INST OF TECH"),
            entry(RegistryKind::MaL, "080030", "CERN"),
            entry(RegistryKind::MaL, "0001C8", "THOMAS CONRAD CORP."),
            entry(RegistryKind::MaL, "0001C8", "CONRAD CORP."),
        ];
        let built = build_db_detailed(&entries, date()).expect("synthetic entries encode");
        assert_eq!(built.stats.dropped_duplicates.len(), 2);
        // Sorted by (length class, prefix): 0001C8 first, then 080030.
        let conrad = &built.stats.dropped_duplicates[0];
        assert_eq!(conrad.assignment, "0001C8");
        assert_eq!(conrad.kept, "CONRAD CORP.");
        assert_eq!(conrad.dropped, ["THOMAS CONRAD CORP."]);
        let cern = &built.stats.dropped_duplicates[1];
        assert_eq!(cern.assignment, "080030");
        assert_eq!(cern.kept, "CERN");
        assert_eq!(
            cern.dropped,
            [
                "NETWORK RESEARCH CORPORATION",
                "ROYAL MELBOURNE INST OF TECH"
            ]
        );

        let db = load(&built.bytes);
        assert_eq!(db.entry_count(), 2);
        let mac: MacAddr = "08:00:30:11:22:33".parse().expect("valid MAC");
        assert_eq!(found_name(db.lookup(&mac)), "CERN");
        let mac: MacAddr = "00:01:c8:99:88:77".parse().expect("valid MAC");
        assert_eq!(found_name(db.lookup(&mac)), "CONRAD CORP.");
    }

    #[test]
    fn cross_registry_duplicates_in_the_36_bit_table_follow_merge_order() {
        // Same 36-bit prefix as MA-S and then IAB: the IAB row is later
        // in merge order (D-2), so it wins (D-3).
        let entries = [
            entry(RegistryKind::MaS, "A8BBCCAFA", "S comes first"),
            entry(RegistryKind::Iab, "A8BBCCAFA", "IAB comes second"),
        ];
        let built = build_db_detailed(&entries, date()).expect("synthetic entries encode");
        assert_eq!(built.stats.dropped_duplicates.len(), 1);
        assert_eq!(
            built.stats.dropped_duplicates[0].registry,
            RegistryKind::Iab
        );
        assert_eq!(built.stats.dropped_duplicates[0].kept, "IAB comes second");
        assert_eq!(built.stats.dropped_duplicates[0].dropped, ["S comes first"]);
        let db = load(&built.bytes);
        assert_eq!(
            db.registry_counts(),
            RegistryCounts {
                ma_l: 0,
                ma_m: 0,
                ma_s: 0,
                iab: 1
            }
        );
        assert_eq!(
            found_name(db.lookup(&mac_under(0xA8BBCCAFA, 36, 0x123))),
            "IAB comes second"
        );
    }

    // ---- D-4 entity unescaping -----------------------------------------------

    #[test]
    fn entity_unescaping_replaces_exactly_the_five_entities() {
        assert_eq!(normalize_organization_name("A &amp; B"), "A & B");
        assert_eq!(normalize_organization_name("&quot;Q&quot;"), "\"Q\"");
        assert_eq!(normalize_organization_name("&lt;tag&gt;"), "<tag>");
        assert_eq!(normalize_organization_name("it&apos;s"), "it's");
        assert_eq!(
            normalize_organization_name("all &amp; &lt; &gt; &quot; &apos;"),
            "all & < > \" '"
        );
    }

    #[test]
    fn entity_unescaping_is_a_single_pass() {
        // No double unescape: `&amp;gt;` → `&gt;`, not `>`.
        assert_eq!(normalize_organization_name("&amp;gt;"), "&gt;");
        assert_eq!(normalize_organization_name("&amp;amp;"), "&amp;");
        assert_eq!(normalize_organization_name("&amp;lt;"), "&lt;");
    }

    #[test]
    fn entity_unescaping_keeps_everything_else_verbatim() {
        assert_eq!(normalize_organization_name("plain name"), "plain name");
        assert_eq!(
            normalize_organization_name("&nope; &AMp; &"),
            "&nope; &AMp; &"
        );
        assert_eq!(
            normalize_organization_name("Ünïcödé &amp; Co"),
            "Ünïcödé & Co"
        );
        assert_eq!(normalize_organization_name("  padded  "), "  padded  ");
        assert_eq!(normalize_organization_name(""), "");
    }

    #[test]
    fn unescaped_names_round_trip_through_the_database() {
        // The stored name carries the unescaped `&`; the loader returns
        // it verbatim through DisplayText.
        let entries = [entry(RegistryKind::MaL, "A8BBCC", "A & B <x> \"q\"")];
        let db = load(&build(&entries));
        assert_eq!(
            found_name(db.lookup(&mac_under(0xA8BBCC, 24, 1))),
            "A & B <x> \"q\""
        );
    }

    // ---- D-6 load-time sanitization -------------------------------------------

    #[test]
    fn nbsp_runs_collapse_at_load_time() {
        let entries = [entry(RegistryKind::MaL, "A8BBCC", "A\u{00a0}\u{00a0}B")];
        let db = load(&build(&entries));
        assert_eq!(found_name(db.lookup(&mac_under(0xA8BBCC, 24, 1))), "A B");
    }

    #[test]
    fn long_names_truncate_to_exactly_64_characters() {
        let long_name = "X".repeat(70);
        let entries = [entry(RegistryKind::MaL, "A8BBCC", long_name.as_str())];
        let db = load(&build(&entries));
        let name = found_name(db.lookup(&mac_under(0xA8BBCC, 24, 1)));
        assert_eq!(name.chars().count(), DISPLAY_TEXT_MAX_CHARS);
        assert_eq!(name, "X".repeat(DISPLAY_TEXT_MAX_CHARS));
        // Still a usable entry, not a skipped one.
        assert_eq!(db.entry_count(), 1);
        assert_eq!(db.skipped_entries(), 0);
    }

    #[test]
    fn names_that_sanitize_to_empty_are_skipped_and_counted() {
        // The builder's D-5 guard rejects whitespace-only names, so the
        // empty-after-sanitization case is produced by patching a valid
        // image in place: same length, different bytes ("AB" → "  ").
        let entries = [entry(RegistryKind::MaL, "A8BBCC", "AB")];
        let image = build(&entries);
        let tail = image.len();
        let corrupted = patched(&image, tail - 2, b"  ");
        let db = load(&corrupted);
        assert_eq!(db.skipped_entries(), 1);
        assert_eq!(db.entry_count(), 0);
        assert_eq!(
            db.registry_counts(),
            RegistryCounts {
                ma_l: 0,
                ma_m: 0,
                ma_s: 0,
                iab: 0
            }
        );
        assert_eq!(
            db.lookup(&mac_under(0xA8BBCC, 24, 1)),
            VendorLookup::Unknown
        );
    }

    // ---- D-8 determinism --------------------------------------------------------

    #[test]
    fn building_twice_from_identical_input_is_byte_identical() {
        let entries = synthetic_all_four();
        let first = build_db_detailed(&entries, date()).expect("encodes");
        let second = build_db_detailed(&entries, date()).expect("encodes");
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.stats, second.stats);
        // A third build through the simple wrapper agrees too.
        assert_eq!(build(&entries), first.bytes);
    }

    // ---- DatabaseDate validation -------------------------------------------------

    #[test]
    fn database_date_accepts_real_calendar_dates() {
        for (year, month, day) in [
            (2026, 11, 3),
            (2024, 2, 29), // Gregorian leap year
            (2000, 2, 29), // divisible by 400: leap
            (1904, 2, 29), // divisible by 4, not by 100: leap
            (2026, 1, 31),
            (2026, 4, 30),
            (2026, 12, 31),
            (1, 1, 1),
        ] {
            let date = DatabaseDate::new(year, month, day);
            assert!(date.is_ok(), "{year}-{month}-{day} must be accepted");
        }
    }

    #[test]
    fn database_date_rejects_impossible_dates() {
        for (year, month, day) in [
            (2023, 2, 29), // not a leap year
            (1900, 2, 29), // divisible by 100, not by 400: not leap
            (2026, 2, 30),
            (2026, 4, 31), // 30-day month
            (2026, 13, 1), // month 13
            (2026, 0, 1),  // month 0
            (2026, 1, 0),  // day 0
            (2026, 1, 32), // day 32
            (2026, 11, 32),
        ] {
            let date = DatabaseDate::new(year, month, day);
            assert!(
                matches!(date, Err(VendorDbError::InvalidDate { .. })),
                "{year}-{month}-{day} must be rejected"
            );
        }
    }

    #[test]
    fn database_date_displays_zero_padded() {
        let formatted = DatabaseDate::new(2026, 3, 7).expect("valid date");
        assert_eq!(formatted.to_string(), "2026-03-07");
        assert_eq!(date().to_string(), "2026-11-03");
    }

    // ---- total parser: corrupt images (SR-02, R-9) --------------------------------

    /// A base image with two MA-L, one MA-M and two 36-bit entries.
    fn corruptible_image() -> Vec<u8> {
        let entries = [
            entry(RegistryKind::MaL, "AABBCC", "Alpha"),
            entry(RegistryKind::MaL, "AABBCD", "Alpha Sibling"),
            entry(RegistryKind::MaM, "AABBCC5", "Beta"),
            entry(RegistryKind::MaS, "112233AFA", "Gamma"),
            entry(RegistryKind::Iab, "40D8550D7", "Delta"),
        ];
        build(&entries)
    }

    #[test]
    fn empty_and_short_inputs_are_truncated_errors() {
        assert_eq!(
            VendorDb::from_bytes(&[]),
            Err(VendorDbError::Truncated {
                found: 0,
                expected: HEADER_LEN
            })
        );
        let image = corruptible_image();
        for cut in [1usize, 26, HEADER_LEN - 1] {
            let result = VendorDb::from_bytes(&image[..cut]);
            assert!(
                matches!(result, Err(VendorDbError::Truncated { .. })),
                "cut at {cut} must be a truncation error"
            );
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let image = corruptible_image();
        let result = VendorDb::from_bytes(&patched(&image, 0, b"X"));
        assert_eq!(result, Err(VendorDbError::BadMagic));
    }

    #[test]
    fn unsupported_versions_are_rejected() {
        let image = corruptible_image();
        let result = VendorDb::from_bytes(&patched(&image, 6, &2u16.to_le_bytes()));
        assert_eq!(result, Err(VendorDbError::UnsupportedVersion { found: 2 }));
    }

    #[test]
    fn invalid_dates_in_the_header_are_rejected() {
        let image = corruptible_image();
        let month = VendorDb::from_bytes(&patched(&image, 10, &[13]));
        assert!(matches!(month, Err(VendorDbError::InvalidDate { .. })));
        let day = VendorDb::from_bytes(&patched(&image, 11, &[32]));
        assert!(matches!(day, Err(VendorDbError::InvalidDate { .. })));
        let mut leap_bytes = Vec::new();
        leap_bytes.extend_from_slice(&2023u16.to_le_bytes());
        leap_bytes.push(2);
        leap_bytes.push(29);
        let leap = VendorDb::from_bytes(&patched(&image, 8, &leap_bytes));
        assert!(matches!(leap, Err(VendorDbError::InvalidDate { .. })));
    }

    #[test]
    fn total_length_mismatches_are_typed_errors() {
        let image = corruptible_image();
        let total = le_u32(&image, 48).expect("header is intact");
        // Declared longer than the input: truncation.
        let longer = VendorDb::from_bytes(&patched(&image, 48, &(total + 1).to_le_bytes()));
        assert_eq!(
            longer,
            Err(VendorDbError::Truncated {
                found: image.len(),
                expected: total as usize + 1
            })
        );
        // Declared shorter: inconsistent layout.
        let shorter = VendorDb::from_bytes(&patched(&image, 48, &(total - 1).to_le_bytes()));
        assert!(matches!(shorter, Err(VendorDbError::Layout { .. })));
    }

    #[test]
    fn truncation_at_every_structural_region_is_an_error() {
        let image = corruptible_image();
        let off_table28 = le_u32(&image, 32).expect("header") as usize;
        let off_table36 = le_u32(&image, 36).expect("header") as usize;
        let off_names = le_u32(&image, 40).expect("header") as usize;
        let total = image.len();
        for cut in [
            off_table28 - 1,
            off_table28,
            off_table36 - 1,
            off_table36,
            off_names - 1,
            off_names,
            total - 1,
        ] {
            let result = VendorDb::from_bytes(&image[..cut]);
            assert!(
                matches!(result, Err(VendorDbError::Truncated { .. })),
                "cut at {cut} must be a truncation error"
            );
        }
    }

    #[test]
    fn inconsistent_offsets_and_lengths_are_layout_errors() {
        let image = corruptible_image();
        let off_table28 = le_u32(&image, 32).expect("header");
        // Shift a table offset: the chain no longer lines up.
        let shifted = VendorDb::from_bytes(&patched(
            &image,
            32,
            &(off_table28 + ENTRY28_LEN as u32).to_le_bytes(),
        ));
        assert!(matches!(shifted, Err(VendorDbError::Layout { .. })));
        // Name region length off by one.
        let names_len = le_u32(&image, 44).expect("header");
        let bad_len = VendorDb::from_bytes(&patched(&image, 44, &(names_len + 1).to_le_bytes()));
        assert!(matches!(bad_len, Err(VendorDbError::Layout { .. })));
        // Counts that disagree with the table sizes shift the offsets.
        let count_mal = le_u32(&image, 12).expect("header");
        let bad_count = VendorDb::from_bytes(&patched(&image, 12, &(count_mal + 1).to_le_bytes()));
        assert!(matches!(bad_count, Err(VendorDbError::Layout { .. })));
    }

    #[test]
    fn name_ranges_outside_the_region_are_rejected() {
        let image = corruptible_image();
        let off_table36 = le_u32(&image, 36).expect("header") as usize;
        let names_len = le_u32(&image, 44).expect("header");
        // First 36-bit entry's name_off points far past the region.
        let far = VendorDb::from_bytes(&patched(
            &image,
            off_table36 + 9,
            &(names_len + 100).to_le_bytes(),
        ));
        assert!(matches!(far, Err(VendorDbError::NameRange { .. })));
        // name_len overruns the region end.
        let name_len = le_u16(&image, off_table36 + 13).expect("entry intact");
        let long = VendorDb::from_bytes(&patched(
            &image,
            off_table36 + 13,
            &(name_len + 10).to_le_bytes(),
        ));
        assert!(matches!(long, Err(VendorDbError::NameRange { .. })));
    }

    #[test]
    fn invalid_utf8_in_the_name_region_is_rejected() {
        let entries = [entry(RegistryKind::MaL, "A8BBCC", "Alpha")];
        let image = build(&entries);
        let tail = image.len();
        let result = VendorDb::from_bytes(&patched(&image, tail - 1, &[0xFF]));
        assert_eq!(result, Err(VendorDbError::InvalidUtf8));
    }

    #[test]
    fn name_slices_must_start_on_character_boundaries() {
        // A two-byte first character: shifting name_off by one slices
        // mid-sequence, which `str::get` rejects.
        let entries = [entry(RegistryKind::MaL, "A8BBCC", "Étude")];
        let image = build(&entries);
        let off_table24 = le_u32(&image, 28).expect("header") as usize;
        let result = VendorDb::from_bytes(&patched(&image, off_table24 + 5, &1u32.to_le_bytes()));
        assert!(matches!(result, Err(VendorDbError::NameRange { .. })));
    }

    #[test]
    fn unsorted_or_duplicated_keys_are_rejected() {
        let image = corruptible_image();
        let off_table24 = le_u32(&image, 28).expect("header") as usize;
        // Second MA-L entry key smaller than the first.
        let descending = patched(&image, off_table24 + ENTRY24_LEN, &1u32.to_le_bytes());
        assert_eq!(
            VendorDb::from_bytes(&descending),
            Err(VendorDbError::Unsorted)
        );
        // Equal keys are equally unsorted (D-3 keys are unique).
        let first_key = le_u32(&image, off_table24).expect("entry intact");
        let equal = patched(&image, off_table24 + ENTRY24_LEN, &first_key.to_le_bytes());
        assert_eq!(VendorDb::from_bytes(&equal), Err(VendorDbError::Unsorted));
    }

    #[test]
    fn invalid_registry_tags_are_rejected() {
        let image = corruptible_image();
        let off_table24 = le_u32(&image, 28).expect("header") as usize;
        let result = VendorDb::from_bytes(&patched(&image, off_table24 + 4, &[9]));
        assert_eq!(result, Err(VendorDbError::InvalidRegistryTag { found: 9 }));
        // A 36-bit MA-S tag turned into an IAB tag keeps the layout but
        // breaks the per-registry census.
        let off_table36 = le_u32(&image, 36).expect("header") as usize;
        let census = VendorDb::from_bytes(&patched(&image, off_table36 + 8, &[TAG_IAB]));
        assert_eq!(census, Err(VendorDbError::CountMismatch));
    }

    #[test]
    fn keys_outside_their_table_width_are_rejected() {
        let image = corruptible_image();
        let off_table24 = le_u32(&image, 28).expect("header") as usize;
        // 2^24 does not fit the 24-bit table.
        let result =
            VendorDb::from_bytes(&patched(&image, off_table24, &(1u32 << 24).to_le_bytes()));
        assert_eq!(
            result,
            Err(VendorDbError::InvalidKey {
                found: 1 << 24,
                bits: 24
            })
        );
        let off_table28 = le_u32(&image, 32).expect("header") as usize;
        let result =
            VendorDb::from_bytes(&patched(&image, off_table28, &(1u32 << 28).to_le_bytes()));
        assert_eq!(
            result,
            Err(VendorDbError::InvalidKey {
                found: 1 << 28,
                bits: 28
            })
        );
        let off_table36 = le_u32(&image, 36).expect("header") as usize;
        let result =
            VendorDb::from_bytes(&patched(&image, off_table36, &(1u64 << 36).to_le_bytes()));
        assert_eq!(
            result,
            Err(VendorDbError::InvalidKey {
                found: 1 << 36,
                bits: 36
            })
        );
    }

    #[test]
    fn reserved_bytes_must_be_zero() {
        let image = corruptible_image();
        let off_table24 = le_u32(&image, 28).expect("header") as usize;
        let result = VendorDb::from_bytes(&patched(&image, off_table24 + ENTRY24_LEN - 1, &[1]));
        assert!(matches!(result, Err(VendorDbError::Layout { .. })));
        let off_table36 = le_u32(&image, 36).expect("header") as usize;
        let result = VendorDb::from_bytes(&patched(&image, off_table36 + ENTRY36_LEN - 1, &[1]));
        assert!(matches!(result, Err(VendorDbError::Layout { .. })));
    }

    // ---- property-style tests (deterministic, std-only) -----------------------------

    /// Property: lookup never panics on any sender MAC (thousands of
    /// random addresses against the committed database).
    #[test]
    fn property_lookup_never_panics_on_random_macs() {
        let db = VendorDb::embedded().expect("the committed database must load");
        let mut rng = Lcg::seeded(0x0E01_2026);
        let mut private = 0usize;
        let mut global = 0usize;
        for _ in 0..4096 {
            let mac = random_mac(&mut rng);
            match db.lookup(&mac) {
                VendorLookup::PrivateAddress => private += 1,
                VendorLookup::Found { .. } | VendorLookup::Unknown => global += 1,
            }
        }
        // The generator covers both branches (guard against vacuity).
        assert!(private > 0, "no locally-administered MAC generated");
        assert!(global > 0, "no globally-administered MAC generated");
    }

    /// Property: a MAC constructed under a random entry's prefix resolves
    /// to that entry's name when no longer-prefix entry exists (a
    /// single-entry database guarantees that).
    #[test]
    fn property_random_prefix_resolves_to_its_owner() {
        let kinds = [
            RegistryKind::MaL,
            RegistryKind::MaM,
            RegistryKind::MaS,
            RegistryKind::Iab,
        ];
        let mut rng = Lcg::seeded(0x0E02_2026);
        for trial in 0..64u64 {
            let kind = kinds[(trial % 4) as usize];
            let bits = kind.bits();
            let shift = 48 - u32::from(bits);
            // Clear the multicast and locally-administered bits of the
            // first octet so MACs under the prefix are valid senders.
            let key = rng.next_below(1 << bits) & !(0x3u64 << (bits - 8));
            let name = format!("Owner {trial}");
            let assignment = format!("{:0width$X}", key, width = kind.digits());
            let entries = [entry(kind, &assignment, &name)];
            let db = load(&build(&entries));
            let expected =
                DisplayText::try_from(name.as_str()).expect("plain names sanitize to themselves");
            for _ in 0..16 {
                let low = rng.next_below(1 << shift);
                let mac = mac_under(key, bits, low);
                assert!(
                    matches!(&db.lookup(&mac), VendorLookup::Found { name } if *name == expected),
                    "trial {trial}: {mac} under {assignment} must resolve to {name}"
                );
            }
        }
    }

    /// Property: the loader is total on hostile images — random
    /// single-byte corruptions of a valid image never panic.
    #[test]
    fn property_random_corruption_never_panics() {
        let mut rng = Lcg::seeded(0x0E03_2026);
        let image = corruptible_image();
        for _ in 0..2000 {
            let position = rng.next_below(image.len() as u64) as usize;
            let byte = rng.next_u8();
            let corrupted = patched(&image, position, &[byte]);
            // Ok or Err, never a panic (SR-02).
            let _ = VendorDb::from_bytes(&corrupted);
        }
    }

    // ---- controlled vocabulary (§5.4 / §11.7) ---------------------------------------

    /// Every string this module can surface (error `Display` forms,
    /// registry labels, the date format) stays inside plan §5.4's
    /// controlled vocabulary.
    #[test]
    fn wording_follows_the_controlled_vocabulary() {
        const BANNED: [&str; 14] = [
            "online",
            "offline",
            "connected",
            "disconnected",
            "intruder",
            "unauthorized",
            "rogue",
            "suspicious",
            "malicious",
            "safe",
            "trusted",
            "secure",
            "verified",
            "stale",
        ];
        let texts: Vec<String> = vec![
            VendorDbError::Truncated {
                found: 1,
                expected: 2,
            }
            .to_string(),
            VendorDbError::BadMagic.to_string(),
            VendorDbError::UnsupportedVersion { found: 2 }.to_string(),
            VendorDbError::InvalidDate {
                year: 2026,
                month: 13,
                day: 1,
            }
            .to_string(),
            VendorDbError::Layout {
                fault: "vendor database layout is inconsistent",
            }
            .to_string(),
            VendorDbError::InvalidRegistryTag { found: 9 }.to_string(),
            VendorDbError::InvalidKey { found: 1, bits: 24 }.to_string(),
            VendorDbError::Unsorted.to_string(),
            VendorDbError::CountMismatch.to_string(),
            VendorDbError::NameRange { offset: 1, len: 2 }.to_string(),
            VendorDbError::InvalidUtf8.to_string(),
            VendorDbError::TooLarge.to_string(),
            VendorEntryError::InvalidAssignment {
                registry: RegistryKind::MaL,
                assignment: "nope".to_owned(),
                digits: 6,
            }
            .to_string(),
            VendorEntryError::EmptyName.to_string(),
            RegistryKind::MaL.to_string(),
            RegistryKind::MaM.to_string(),
            RegistryKind::MaS.to_string(),
            RegistryKind::Iab.to_string(),
            date().to_string(),
        ];
        assert!(!texts.is_empty());
        for text in &texts {
            for word in BANNED {
                assert!(
                    !text.to_lowercase().contains(word),
                    "banned word {word:?} surfaced in {text:?}"
                );
            }
        }
    }

    // ---- VendorEntry boundary --------------------------------------------------------

    #[test]
    fn vendor_entry_rejects_malformed_assignments() {
        for (kind, assignment) in [
            (RegistryKind::MaL, "AABBC"),    // too short
            (RegistryKind::MaL, "AABBCCD"),  // too long
            (RegistryKind::MaL, "AABBCG"),   // not hexadecimal
            (RegistryKind::MaM, "AABBCC"),   // 6 digits, needs 7
            (RegistryKind::MaS, "112233AF"), // 8 digits, needs 9
            (RegistryKind::Iab, ""),         // empty
            (RegistryKind::MaL, "AA BB CC"), // separators
        ] {
            let result = VendorEntry::new(kind, assignment, "Name");
            assert!(
                matches!(result, Err(VendorEntryError::InvalidAssignment { .. })),
                "{assignment:?} for {kind} must be rejected"
            );
        }
        // Case-insensitive hexadecimal is fine, and the assignment
        // round-trips in the canonical uppercase form.
        let lower = VendorEntry::new(RegistryKind::MaL, "aabbcc", "Name")
            .expect("lowercase hexadecimal is valid");
        assert_eq!(lower.assignment(), "AABBCC");
        assert_eq!(lower.registry(), RegistryKind::MaL);
        assert_eq!(lower.name(), "Name");
    }

    #[test]
    fn vendor_entry_rejects_empty_names() {
        for name in ["", " ", "\t\n", "\u{00a0}"] {
            let result = VendorEntry::new(RegistryKind::MaL, "AABBCC", name);
            assert_eq!(result, Err(VendorEntryError::EmptyName), "name {name:?}");
        }
    }

    // ---- real data (the committed embedded database) ---------------------------------
    //
    // NOTE (task card R-9): the expectations below are pinned to the
    // committed database image (data/oui/vendor-db.bin, retrieved
    // 2026-11-03 — see data/oui/SOURCE.md). They are stable legacy facts;
    // if the database is ever refreshed from newer IEEE CSVs, updating
    // these expectations is part of that refresh.

    fn expect_found(mac_text: &str, expected: &str) {
        let db = VendorDb::embedded().expect("the committed database must load");
        let mac: MacAddr = mac_text.parse().expect("valid MAC");
        match db.lookup(&mac) {
            VendorLookup::Found { name } => {
                assert_eq!(name.as_str(), expected, "MAC {mac_text}")
            }
            other => panic!("expected Found for {mac_text}, got {other:?}"),
        }
    }

    #[test]
    fn one_real_lookup_per_registry_class() {
        // MA-L 28:6F:B9 (Nokia Shanghai Bell).
        expect_found("28:6f:b9:00:00:01", "Nokia Shanghai Bell Co., Ltd.");
        // MA-M C8:5C:E2:7 (SYNERGY SYSTEMS AND SOLUTIONS holds C85CE27).
        expect_found("c8:5c:e2:71:02:03", "SYNERGY SYSTEMS AND SOLUTIONS");
        // MA-S 8C:1F:64:AF:A (DATA ELECTRONIC DEVICES).
        expect_found("8c:1f:64:af:a0:11", "DATA ELECTRONIC DEVICES, INC");
        // IAB 40:D8:55:0D:7 (Avant Technologies).
        expect_found("40:d8:55:0d:70:01", "Avant Technologies");
    }

    #[test]
    fn the_real_overlap_pair_resolves_both_ways() {
        // C8:5C:E2 is an MA-L assignment to IEEE Registration Authority,
        // and 15 of its 16 28-bit children are assigned MA-M blocks; the
        // assigned child wins (longest prefix)…
        expect_found("c8:5c:e2:e0:aa:01", "Wonder Education Tech Limited");
        // …while the one unassigned child (C85CE2F in this data) falls
        // back to the 24-bit parent.
        expect_found("c8:5c:e2:f0:aa:01", "IEEE Registration Authority");
    }

    #[test]
    fn duplicate_prefixes_resolve_to_the_current_holder() {
        expect_found("08:00:30:11:22:33", "CERN");
        expect_found("00:01:c8:99:88:77", "CONRAD CORP.");
    }

    #[test]
    fn private_registrations_are_kept_verbatim() {
        // D-5: IEEE privacy registrations are stored verbatim (239 in the
        // source data); E4F14C is one of them.
        expect_found("e4:f1:4c:11:22:33", "Private");
    }

    #[test]
    fn locally_administered_real_mac_answers_private_address() {
        let db = VendorDb::embedded().expect("the committed database must load");
        let mac: MacAddr = "02:28:6f:b9:12:34".parse().expect("valid MAC");
        assert_eq!(db.lookup(&mac), VendorLookup::PrivateAddress);
    }

    #[test]
    fn unassigned_real_prefix_answers_unknown() {
        let db = VendorDb::embedded().expect("the committed database must load");
        // ECECEC is unassigned at every length in the source data.
        let mac: MacAddr = "ec:ec:ec:11:22:33".parse().expect("valid MAC");
        assert_eq!(db.lookup(&mac), VendorLookup::Unknown);
    }

    #[test]
    fn the_embedded_database_is_self_consistent() {
        let db = VendorDb::embedded().expect("the committed database must load");
        let counts = db.registry_counts();
        assert_eq!(
            db.entry_count(),
            counts.ma_l + counts.ma_m + counts.ma_s + counts.iab
        );
        // Header total minus skipped entries (expected 0 today, D-6).
        assert_eq!(db.skipped_entries(), 0);
        // The committed baseline: 58,946 source rows, 3 dropped as
        // duplicates (D-3), 58,943 stored — refresh-sensitive numbers,
        // recorded in data/oui/SOURCE.md.
        assert_eq!(
            (counts.ma_l, counts.ma_m, counts.ma_s, counts.iab),
            (40_439, 6_668, 7_261, 4_575)
        );
        assert_eq!(db.entry_count(), 58_943);
        assert_eq!(db.database_date().to_string(), "2026-11-03");
    }
}
