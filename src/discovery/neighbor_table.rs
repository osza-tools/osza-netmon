// SPDX-License-Identifier: GPL-3.0-only

//! Kernel neighbor-table reader: `/proc/net/arp` (plan §6.3 FR-DS-01,
//! FR-DS-02, §7.2 SR-10, Appendix E; task T-102).
//!
//! FR-DS-01 has every scan cycle read the kernel neighbor table before
//! the ARP sweep — instant first rows — and again after it. This module
//! is that reader for the `/proc/net/arp` source, the interim ADR-010
//! path the plan fixes for T-102; whether a netlink `RTM_GETNEIGH`
//! source joins it (its `reachable`/`stale`/`failed` states) is T-105's
//! decision, and [`NeighborSource`] is shaped so such a source can be
//! implemented alongside without touching the trait signature.
//!
//! The read pipeline is total, read-only and std-only (plan SR-02,
//! §2.3, task card §8):
//!
//! 1. open the file and read at most 64 KiB (SR-10 — a real table has
//!    one short line per neighbor; hostile or oversized content is
//!    truncated before parsing);
//! 2. decode the bytes as UTF-8, lossily — every column is validated, so
//!    a line containing bytes that are not valid UTF-8 cannot pass any
//!    column check and is skipped whole;
//! 3. parse every line after the header (Appendix E columns: `IP
//!    address · HW type · Flags · HW address · Mask · Device`),
//!    validating all six columns; a malformed line is skipped whole,
//!    never repaired;
//! 4. build the MAC through [`MacAddr::from_octets`], the T-002 boundary
//!    that rejects all-zero, broadcast and multicast senders;
//! 5. filter per FR-DS-02 — selected interface only, IP inside the
//!    scope, complete entries only.
//!
//! No socket is opened and no packet is sent (§2.3); the first active
//! network code belongs to T-104. Per §8.2 this module depends only on
//! `model`.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::model::ipv4::Ipv4Net;
use crate::model::mac::MacAddr;

/// The kernel's IPv4 neighbor (ARP) table (plan Appendix E).
const ARP_TABLE_PATH: &str = "/proc/net/arp";

/// Upper bound accepted when reading the neighbor table (SR-10): a real
/// table is a few KiB; anything beyond this bound is not read at all, so
/// hostile or oversized content cannot grow the reader's memory beyond a
/// fixed cap.
const ARP_TABLE_MAX_BYTES: u64 = 64 * 1024;

/// `ATF_COM` — "completed entry (`ha` valid)" from
/// `include/linux/if_arp.h`; plan Appendix E: Flags `0x2` = complete.
const ATF_COM: u32 = 0x2;

// ---------------------------------------------------------------------------
// Output and error types
// ---------------------------------------------------------------------------

/// One row of the kernel neighbor table, already reduced to the §5.3
/// sender rules (FR-DS-02 output side).
///
/// A `NeighborEntry` can only be built by [`parse_arp_table`] and
/// [`filter_neighbors`] (or, inside tests, by struct literal): the `mac`
/// field is a [`MacAddr`], so it is always a valid unicast sender
/// address — all-zero, broadcast and multicast hardware addresses never
/// become entries (they are rejected by the T-002 boundary constructor).
///
/// The other three FR-DS-02 filters — selected interface, IP inside the
/// scope, completeness — are applied by [`filter_neighbors`], which
/// [`ProcNeighborTable::read_neighbors`] calls after parsing.
///
/// The registry task (T-201) will wrap these rows into
/// `Field::Known { source: Source::NeighborTable, .. }` values (plan
/// §5.1); this module returns the raw observations, in file order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NeighborEntry {
    /// The neighbor's IPv4 address (`IP address` column).
    ip: Ipv4Addr,
    /// The validated hardware address (`HW address` column).
    mac: MacAddr,
    /// The raw hardware type (`HW type` column, e.g. `0x1` for
    /// Ethernet). Kept for diagnostics and the T-105 source comparison;
    /// classification lives in the `net` layer (`LinkType`), which this
    /// module must not depend on (§8.2).
    hw_type: u32,
    /// The raw kernel flags (`Flags` column). `0x2` (`ATF_COM`) means
    /// the entry is complete; other bits (`0x4` permanent, `0x8`
    /// publish, …) are kept for future use (task card R5).
    flags: u32,
    /// The interface the entry was learned on (`Device` column).
    device: String,
}

impl NeighborEntry {
    /// The neighbor's IPv4 address (`IP address` column).
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// The validated hardware address (`HW address` column); always a
    /// valid unicast sender MAC.
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// The raw hardware type (`HW type` column; `1` = Ethernet).
    pub fn hw_type(&self) -> u32 {
        self.hw_type
    }

    /// The raw kernel flags (`Flags` column), preserved bit for bit.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// The interface the entry was learned on (`Device` column).
    pub fn device(&self) -> &str {
        &self.device
    }

    /// `true` when the complete bit (`ATF_COM`, `0x2`) is set — the
    /// kernel has a resolved hardware address for this neighbor. This is
    /// the completeness predicate of FR-DS-02.
    pub fn is_complete(&self) -> bool {
        self.flags & ATF_COM != 0
    }
}

/// Errors returned while reading a neighbor source.
///
/// Hand-rolled with `std` only (task card §8: this task adds no crates);
/// the single variant carries the offending path and the underlying
/// [`io::Error`] as its `source`.
#[derive(Debug)]
pub enum NeighborError {
    /// Reading the neighbor-table file at `path` failed (missing file,
    /// permission denied, I/O error).
    Io {
        /// The path that was being read.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for NeighborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NeighborError::Io { path, source } => write!(
                f,
                "reading the neighbor table at {} failed: {}",
                path.display(),
                source
            ),
        }
    }
}

impl Error for NeighborError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NeighborError::Io { source, .. } => Some(source),
        }
    }
}

// ---------------------------------------------------------------------------
// The source trait (FR-DS-01)
// ---------------------------------------------------------------------------

/// A source of neighbor information (plan §6.3 FR-DS-01).
///
/// Implementations return the neighbors of one interface inside one scan
/// scope, already reduced to the FR-DS-02 output contract: selected
/// interface only, IP inside the scope, complete entries only, valid
/// unicast MACs only. Callers never see rejected rows.
///
/// The trait is deliberately small and object-safe, and it carries no
/// transport-specific types: the future netlink source of ADR-010
/// (decided by T-105) can resolve the interface name to an index and map
/// neighbor states internally, implementing this same method without a
/// signature change (task card R10).
pub trait NeighborSource {
    /// Reads the neighbors of `interface_name` that lie inside `scope`.
    ///
    /// Reading is a pure observation: no packet is sent, nothing is
    /// cached, and two calls return independent snapshots.
    fn read_neighbors(
        &self,
        scope: &Ipv4Net,
        interface_name: &str,
    ) -> Result<Vec<NeighborEntry>, NeighborError>;
}

// ---------------------------------------------------------------------------
// The /proc/net/arp source (ADR-010 interim path)
// ---------------------------------------------------------------------------

/// The kernel neighbor table exposed as `/proc/net/arp` (plan §4,
/// ADR-010's interim implementation path for T-102).
///
/// The file is read at most once per call, bounded by 64 KiB (SR-10),
/// and treated as untrusted input end to end (Appendix E). Use
/// [`ProcNeighborTable::from_path`] to read a fixture instead of the
/// live kernel table.
///
/// # Examples
///
/// ```no_run
/// use std::net::Ipv4Addr;
///
/// use osza_netmon::discovery::neighbor_table::{NeighborSource, ProcNeighborTable};
/// use osza_netmon::model::ipv4::Ipv4Net;
///
/// let table = ProcNeighborTable::new();
/// let scope = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid network");
/// let neighbors = table
///     .read_neighbors(&scope, "eth0")
///     .expect("the kernel neighbor table is readable");
/// for entry in &neighbors {
///     // FR-DS-02: every entry is complete, on eth0, inside the scope,
///     // and carries a valid unicast MAC.
///     assert!(entry.is_complete());
///     assert_eq!(entry.device(), "eth0");
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNeighborTable {
    /// The file this table is read from.
    path: PathBuf,
}

impl ProcNeighborTable {
    /// The live kernel neighbor table at `/proc/net/arp`.
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(ARP_TABLE_PATH),
        }
    }

    /// A neighbor table read from `path` instead of the live kernel
    /// file (tests and fixtures).
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path this table is read from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens and reads the table file, at most `ARP_TABLE_MAX_BYTES`
    /// bytes of it (SR-10). Any I/O failure is reported as
    /// [`NeighborError::Io`] — unlike the T-101 route read, this source
    /// has a `Result` contract, so a caller can tell "no neighbors"
    /// from "the table could not be read".
    fn read_table(&self) -> Result<Vec<u8>, NeighborError> {
        let file = File::open(&self.path).map_err(|source| NeighborError::Io {
            path: self.path.clone(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.take(ARP_TABLE_MAX_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|source| NeighborError::Io {
                path: self.path.clone(),
                source,
            })?;
        Ok(bytes)
    }
}

impl Default for ProcNeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborSource for ProcNeighborTable {
    fn read_neighbors(
        &self,
        scope: &Ipv4Net,
        interface_name: &str,
    ) -> Result<Vec<NeighborEntry>, NeighborError> {
        let bytes = self.read_table()?;
        Ok(neighbors_from_bytes(&bytes, scope, interface_name))
    }
}

// ---------------------------------------------------------------------------
// Parsing (Appendix E) and filtering (FR-DS-02)
// ---------------------------------------------------------------------------

/// Parses the text of `/proc/net/arp` (plan Appendix E).
///
/// The format is `IP address · HW type · Flags · HW address · Mask ·
/// Device`; the first line is the header and is skipped. The IP column
/// is dotted-decimal; HW type and Flags are `0x`-prefixed hexadecimal;
/// the HW address is six `:`- or `-`-separated hex octets (the kernel
/// writes colons); the Mask is `*` or a dotted-decimal netmask; the
/// Device column is an interface name.
///
/// The parser is total (plan SR-02) and tolerant exactly as Appendix E
/// requires ("ignore unknown columns; tolerate any whitespace; treat the
/// file as untrusted"):
///
/// * any run of whitespace separates two columns (tabs and CRLF files
///   parse too);
/// * a line with fewer than six columns is skipped whole;
/// * a line where **any** column is invalid for its type is skipped
///   whole — including the Mask column, which must be `*` or a
///   dotted-quad (the T-101 "validate every column" discipline);
/// * columns beyond the six the kernel defines are ignored;
/// * a line whose HW address fails the §5.3 sender rules (all-zero,
///   broadcast, multicast) produces no entry — [`MacAddr::from_octets`]
///   is the boundary;
/// * empty input (or a header-only file) yields an empty vector.
///
/// # Examples
///
/// ```
/// use osza_netmon::discovery::neighbor_table::parse_arp_table;
///
/// // Synthetic fixture: RFC 5737 address, documentation MAC (plan §14.3 rule 8).
/// let table = parse_arp_table(
///     "IP address       HW type     Flags       HW address          Mask   Device\n\
///      192.0.2.10       0x1         0x2         aa:bb:cc:dd:ee:ff   *        eth0\n",
/// );
/// assert_eq!(
///     table.first().map(|entry| entry.ip().to_string()),
///     Some("192.0.2.10".to_owned())
/// );
/// assert_eq!(
///     table.first().map(|entry| entry.mac().to_string()),
///     Some("aa:bb:cc:dd:ee:ff".to_owned())
/// );
/// assert!(table.first().is_some_and(|entry| entry.is_complete()));
/// ```
pub fn parse_arp_table(content: &str) -> Vec<NeighborEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(line_number, line)| {
            if line_number == 0 {
                // Line 0 is the header (`IP address HW type …`); the
                // kernel always writes it (Appendix E), so it is skipped
                // unconditionally — the same rule as `parse_routes`.
                None
            } else {
                parse_line(line)
            }
        })
        .collect()
}

/// Applies the FR-DS-02 filters to already-parsed entries: keep only
/// entries of `interface_name` whose IP lies inside `scope` and whose
/// flags carry the complete bit (`ATF_COM`, `0x2`).
///
/// The checks are applied in the task card's order — interface, scope,
/// completeness — and all of them must pass. The fourth FR-DS-02 filter,
/// the MAC boundary, is enforced earlier, by construction: a
/// [`NeighborEntry`] can only exist with a valid unicast sender MAC.
/// Rows are neither reordered nor deduplicated; merging duplicates is
/// the registry's job (T-201).
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
///
/// use osza_netmon::discovery::neighbor_table::{filter_neighbors, parse_arp_table};
/// use osza_netmon::model::ipv4::Ipv4Net;
///
/// let table = parse_arp_table(
///     "IP address       HW type     Flags       HW address          Mask   Device\n\
///      192.0.2.1        0x1         0x2         aa:bb:cc:dd:ee:01   *        eth0\n\
///      192.0.2.2        0x1         0x0         aa:bb:cc:dd:ee:02   *        eth0\n",
/// );
/// let scope = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid network");
/// let kept = filter_neighbors(table, &scope, "eth0");
/// assert_eq!(kept.len(), 1, "the incomplete entry is dropped");
/// ```
pub fn filter_neighbors<I>(entries: I, scope: &Ipv4Net, interface_name: &str) -> Vec<NeighborEntry>
where
    I: IntoIterator<Item = NeighborEntry>,
{
    entries
        .into_iter()
        .filter(|entry| {
            // FR-DS-02, in task-card order: interface, scope,
            // completeness. `Ipv4Net::contains` includes the network and
            // broadcast addresses.
            entry.device == interface_name && scope.contains(entry.ip) && entry.is_complete()
        })
        .collect()
}

/// The full in-memory pipeline of [`ProcNeighborTable::read_neighbors`]:
/// lossy UTF-8 decode, parse, filter. Exercised directly by the tests so
/// the fixture suites cover everything except the file open itself.
fn neighbors_from_bytes(bytes: &[u8], scope: &Ipv4Net, interface_name: &str) -> Vec<NeighborEntry> {
    let content = String::from_utf8_lossy(bytes);
    filter_neighbors(parse_arp_table(&content), scope, interface_name)
}

/// Parses one non-header line of `/proc/net/arp`.
///
/// Total: anything that is not a complete, well-formed kernel row —
/// with a hardware address that passes the §5.3 sender rules — maps to
/// `None`; nothing is repaired, nothing panics (SR-02).
fn parse_line(line: &str) -> Option<NeighborEntry> {
    // Any run of whitespace separates two columns (Appendix E); a line
    // that cannot supply all six is skipped whole. Columns beyond the
    // six the kernel defines are unknown columns and are ignored, as in
    // `parse_routes`.
    let mut columns = line.split_whitespace();
    let (
        Some(ip_text),
        Some(hw_type_text),
        Some(flags_text),
        Some(hw_address_text),
        Some(mask_text),
        Some(device_text),
    ) = (
        columns.next(),
        columns.next(),
        columns.next(),
        columns.next(),
        columns.next(),
        columns.next(),
    )
    else {
        return None;
    };
    // Every column must be valid for its type — one bad column marks
    // the whole line as not kernel output, and it is skipped (the
    // T-101 parsing discipline; the columns this layer does not store
    // are validated too).
    let ip = parse_ipv4_decimal(ip_text)?;
    let hw_type = parse_prefixed_hex(hw_type_text)?;
    let flags = parse_prefixed_hex(flags_text)?;
    let hw_address = parse_mac_octets(hw_address_text)?;
    if !is_valid_mask(mask_text) || !is_kernel_device_name(device_text) {
        return None;
    }
    // §5.3 boundary: all-zero, broadcast and multicast senders are
    // rejected by the validating constructor, never repaired.
    let mac = MacAddr::from_octets(hw_address).ok()?;
    Some(NeighborEntry {
        ip,
        mac,
        hw_type,
        flags,
        device: device_text.to_owned(),
    })
}

/// Parses the kernel's dotted-decimal IPv4 notation: exactly four octets
/// of 1–3 ASCII digits with no leading zeros (the kernel's `%pI4`
/// format never emits them), each in `0..=255`.
fn parse_ipv4_decimal(text: &str) -> Option<Ipv4Addr> {
    let mut fields = text.split('.');
    let mut octets = [0u8; 4];
    for slot in octets.iter_mut() {
        let field = fields.next()?;
        let digits = field.as_bytes();
        if digits.is_empty() || digits.len() > 3 {
            return None;
        }
        if !digits.iter().all(|digit| digit.is_ascii_digit()) {
            return None;
        }
        if digits.len() > 1 && field.starts_with('0') {
            return None;
        }
        let mut value = 0u32;
        for digit in digits {
            value = value * 10 + u32::from(digit - b'0');
        }
        *slot = u8::try_from(value).ok()?;
    }
    if fields.next().is_some() {
        return None;
    }
    let [a, b, c, d] = octets;
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Parses the kernel's `0x`-prefixed hexadecimal notation used by the
/// HW type and Flags columns (e.g. `0x2`, `0x0`, `0x6`): digits of
/// either case, at most a `u32`. A value without the prefix is not
/// kernel output and is rejected.
fn parse_prefixed_hex(text: &str) -> Option<u32> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for digit in digits.bytes() {
        value = value
            .checked_mul(16)?
            .checked_add(u32::from(hex_value(digit)?))?;
    }
    Some(value)
}

/// Hex digit value of `byte`, or `None` for any non-hex byte. UTF-8
/// continuation bytes of multi-byte characters land here and are
/// rejected, so non-ASCII input cannot slip through as digits.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses the HW address column: six two-digit hex octets separated by
/// `:` (the kernel's form in `/proc/net/arp`) or `-`. The bare 12-digit
/// form is not used by this file, and mixed separators are rejected —
/// the same rules as `MacAddr`'s own parser.
fn parse_mac_octets(text: &str) -> Option<[u8; 6]> {
    let has_colon = text.contains(':');
    let has_dash = text.contains('-');
    if has_colon == has_dash {
        // Both separators mixed, or neither (bare or no separator).
        return None;
    }
    let separator = if has_colon { ':' } else { '-' };
    if text.split(separator).count() != 6 {
        return None;
    }
    let mut octets = [0u8; 6];
    for (index, field) in text.split(separator).enumerate() {
        let mut digits = field.bytes();
        let high = hex_value(digits.next()?)?;
        let low = hex_value(digits.next()?)?;
        if digits.next().is_some() {
            return None;
        }
        *octets.get_mut(index)? = high * 16 + low;
    }
    Some(octets)
}

/// The Mask column: the kernel writes `*` for ordinary entries or a
/// dotted-decimal netmask for entries installed with one.
fn is_valid_mask(text: &str) -> bool {
    text == "*" || parse_ipv4_decimal(text).is_some()
}

/// The Device column must be a name the kernel could have created. This
/// mirrors `dev_valid_name()` (`net/core/dev.c`): 1..=15 bytes
/// (`IFNAMSIZ` counts the NUL terminator), no `/` or `:`, and neither
/// `.` nor `..`. A token that fails this cannot name a real interface —
/// the "unknown device" of the task card's malformed list. (Tokens with
/// other unusual characters still parse; the FR-DS-02 interface filter
/// requires an exact match with the selected interface, so they can
/// never reach a caller.)
fn is_kernel_device_name(text: &str) -> bool {
    text.len() < 16 && text != "." && text != ".." && !text.contains('/') && !text.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;

    /// Header of `/proc/net/arp` exactly as the kernel writes it (plan
    /// Appendix E; the kernel right-pads the columns with spaces — the
    /// parser splits on whitespace runs).
    const ARP_HEADER: &str =
        "IP address       HW type     Flags       HW address          Mask   Device";

    /// A realistic synthetic table (RFC 5737 ranges and documentation
    /// MACs, plan §14.3 rule 8): three FR-DS-02 keepers on
    /// eth0/192.0.2.0/24, one incomplete entry, one out-of-scope entry
    /// and one entry on another interface.
    const REALISTIC_TABLE: &str = concat!(
        "IP address       HW type     Flags       HW address          Mask   Device\n",
        "192.0.2.1        0x1         0x2         aa:bb:cc:dd:ee:01   *        eth0\n",
        "192.0.2.17       0x1         0x2         02:11:22:33:44:55   *        eth0\n",
        "192.0.2.254      0x1         0x6         aa:bb:cc:dd:ee:fe   *        eth0\n",
        "192.0.2.9        0x1         0x0         aa:bb:cc:dd:ee:09   *        eth0\n",
        "198.51.100.7     0x1         0x2         aa:bb:cc:dd:ee:07   *        eth0\n",
        "192.0.2.30       0x1         0x2         aa:bb:cc:dd:ee:1e   *        wlan0\n",
    );

    /// The standard fixture scope: RFC 5737 TEST-NET-1.
    fn scope() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("192.0.2.0/24 is valid")
    }

    fn ip(octets: [u8; 4]) -> Ipv4Addr {
        let [a, b, c, d] = octets;
        Ipv4Addr::new(a, b, c, d)
    }

    /// The parsed IPs, in file order.
    fn ips(entries: &[NeighborEntry]) -> Vec<Ipv4Addr> {
        entries.iter().map(|entry| entry.ip()).collect()
    }

    // ---- parse_arp_table (card §6: fixtures, empty input) ------------------

    #[test]
    fn parses_a_realistic_arp_table() {
        let entries = parse_arp_table(REALISTIC_TABLE);
        assert_eq!(
            entries.len(),
            6,
            "all six data lines are structurally valid rows"
        );

        let first = entries.first().expect("row 1");
        assert_eq!(first.ip(), ip([192, 0, 2, 1]));
        assert_eq!(first.hw_type(), 1);
        assert_eq!(first.flags(), 0x2);
        assert_eq!(first.mac().to_string(), "aa:bb:cc:dd:ee:01");
        assert_eq!(first.device(), "eth0");
        assert!(first.is_complete());

        // The locally-administered documentation MAC parses; labeling it
        // `Private address` is the UI's job (FR-EN-01), not this layer's.
        let second = entries.get(1).expect("row 2");
        assert_eq!(second.mac().to_string(), "02:11:22:33:44:55");
        assert!(second.mac().is_locally_administered());

        // 0x6 = permanent + complete: kept, with its raw flags (R5).
        let third = entries.get(2).expect("row 3");
        assert_eq!(third.flags(), 0x6);
        assert!(third.is_complete());

        // Incomplete rows parse — completeness is a FR-DS-02 filter, not
        // a format rule.
        let fourth = entries.get(3).expect("row 4");
        assert_eq!(fourth.flags(), 0x0);
        assert!(!fourth.is_complete());

        // Out-of-scope and other-interface rows parse as well; filtering
        // them is a separate, tested step.
        assert_eq!(entries.get(4).expect("row 5").ip(), ip([198, 51, 100, 7]));
        assert_eq!(entries.get(5).expect("row 6").device(), "wlan0");
    }

    #[test]
    fn full_pipeline_keeps_exactly_the_fr_ds_02_entries() {
        let entries = neighbors_from_bytes(REALISTIC_TABLE.as_bytes(), &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [
                ip([192, 0, 2, 1]),
                ip([192, 0, 2, 17]),
                ip([192, 0, 2, 254])
            ],
            "keepers only: complete, on eth0, inside 192.0.2.0/24"
        );
    }

    #[test]
    fn empty_and_header_only_input_yield_no_entries() {
        assert!(parse_arp_table("").is_empty());
        assert!(parse_arp_table("\n").is_empty());
        assert!(parse_arp_table(ARP_HEADER).is_empty());
        assert!(parse_arp_table(&format!("{ARP_HEADER}\n")).is_empty());
    }

    // ---- FR-DS-02 filters (card §7 AC-2 … AC-6) ----------------------------

    #[test]
    fn incomplete_entries_are_dropped() {
        // AC-2: Flags 0x0 (incomplete) — no complete bit.
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1  0x1  0x0  aa:bb:cc:dd:ee:01  *  eth0\n",
            "192.0.2.2  0x1  0x2  aa:bb:cc:dd:ee:02  *  eth0\n",
        );
        let entries = neighbors_from_bytes(content.as_bytes(), &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 2])],
            "the 0x0 row is dropped"
        );
    }

    #[test]
    fn permanent_only_entries_are_dropped_and_combined_flags_kept() {
        // AC-3: 0x4 alone (permanent, no complete bit) is dropped;
        // 0x6 (permanent + complete) and other complete combinations are
        // kept with their raw flag values.
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.3  0x1  0x4  aa:bb:cc:dd:ee:03  *  eth0\n",
            "192.0.2.4  0x1  0x6  aa:bb:cc:dd:ee:04  *  eth0\n",
            "192.0.2.5  0x1  0xA  aa:bb:cc:dd:ee:05  *  eth0\n",
        );
        let entries = neighbors_from_bytes(content.as_bytes(), &scope(), "eth0");
        assert_eq!(ips(&entries), [ip([192, 0, 2, 4]), ip([192, 0, 2, 5])]);
        assert_eq!(entries.first().expect("0x6 row").flags(), 0x6);
        assert_eq!(
            entries.get(1).expect("0xA row").flags(),
            0xA,
            "other flag bits are preserved for future use (R5)"
        );
    }

    #[test]
    fn entries_on_other_interfaces_are_dropped() {
        // AC-4: exact interface-name match only.
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1  0x1  0x2  aa:bb:cc:dd:ee:01  *  wlan0\n",
            "192.0.2.2  0x1  0x2  aa:bb:cc:dd:ee:02  *  eth1\n",
            "192.0.2.3  0x1  0x2  aa:bb:cc:dd:ee:03  *  eth0x\n",
            "192.0.2.4  0x1  0x2  aa:bb:cc:dd:ee:04  *  ETH0\n",
            "192.0.2.5  0x1  0x2  aa:bb:cc:dd:ee:05  *  eth0\n",
        );
        let entries = neighbors_from_bytes(content.as_bytes(), &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 5])],
            "no prefix match (`eth0x`), no case folding (`ETH0`), no other interface"
        );
    }

    #[test]
    fn out_of_scope_entries_are_dropped() {
        // AC-5: only IPs inside 192.0.2.0/24 survive. `Ipv4Net::contains`
        // includes the network and broadcast addresses (model semantics).
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1    0x1  0x2  aa:bb:cc:dd:ee:01  *  eth0\n",
            "198.51.100.5 0x1  0x2  aa:bb:cc:dd:ee:02  *  eth0\n",
            "203.0.113.9  0x1  0x2  aa:bb:cc:dd:ee:03  *  eth0\n",
            "192.0.3.1    0x1  0x2  aa:bb:cc:dd:ee:04  *  eth0\n",
            "192.0.2.0    0x1  0x2  aa:bb:cc:dd:ee:05  *  eth0\n",
            "192.0.2.255  0x1  0x2  aa:bb:cc:dd:ee:06  *  eth0\n",
        );
        let entries = neighbors_from_bytes(content.as_bytes(), &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 1]), ip([192, 0, 2, 0]), ip([192, 0, 2, 255])],
            "TEST-NET-2/3 and the adjacent /24 are dropped; the /24 edges are inside"
        );
    }

    #[test]
    fn invalid_macs_are_rejected_at_the_boundary() {
        // AC-6: zero, broadcast and multicast sender MACs never become
        // entries — `MacAddr::from_octets` is the boundary (R6) — while
        // locally-administered addresses are valid senders.
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1  0x1  0x2  00:00:00:00:00:00  *  eth0\n",
            "192.0.2.2  0x1  0x2  ff:ff:ff:ff:ff:ff  *  eth0\n",
            "192.0.2.3  0x1  0x2  01:00:5e:0a:0b:0c  *  eth0\n",
            "192.0.2.4  0x1  0x2  33:33:0a:0b:0c:0d  *  eth0\n",
            "192.0.2.5  0x1  0x2  02:0a:0b:0c:0d:0e  *  eth0\n",
            "192.0.2.6  0x1  0x2  aa:bb:cc:dd:ee:06  *  eth0\n",
        );
        let entries = parse_arp_table(content);
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 5]), ip([192, 0, 2, 6])],
            "zero, broadcast, IPv4-multicast (01:00:5e:…) and IPv6-multicast (33:33:…) rows produce no entry"
        );
        assert!(
            entries
                .first()
                .expect("locally-administered row")
                .mac()
                .is_locally_administered()
        );
    }

    // ---- malformed lines (card §6: garbage, AC-7) ---------------------------

    #[test]
    fn malformed_lines_are_skipped_and_valid_lines_are_kept() {
        // Around two well-formed anchor lines: truncated lines, wrong
        // column counts, non-hex flags, flags without the 0x prefix, a
        // u32-overflowing flag word, invalid IPs (octet range, leading
        // zero, wrong field count), malformed MACs (5 octets, non-hex,
        // bare, mixed separators), a non-hex HW type, an invalid mask,
        // impossible device names, an empty line and a bare word. Only
        // the two anchors survive.
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1   0x1  0x2  aa:bb:cc:dd:ee:01  *  eth0\n",
            "192.0.2.2   0x1  0x2\n",
            "192.0.2.3   0x1  0x2  aa:bb:cc:dd:ee:03  *\n",
            "192.0.2.4   0x1  0xZZ aa:bb:cc:dd:ee:04  *  eth0\n",
            "192.0.2.5   0x1  2    aa:bb:cc:dd:ee:05  *  eth0\n",
            "192.0.2.6   0x1  0x100000000  aa:bb:cc:dd:ee:06  *  eth0\n",
            "999.0.2.7   0x1  0x2  aa:bb:cc:dd:ee:07  *  eth0\n",
            "192.0.02.8  0x1  0x2  aa:bb:cc:dd:ee:08  *  eth0\n",
            "192.0.2     0x1  0x2  aa:bb:cc:dd:ee:09  *  eth0\n",
            "192.0.2.10  0x1  0x2  aa:bb:cc:dd:ee     *  eth0\n",
            "192.0.2.11  0x1  0x2  aa:bb:cc:dd:ee:fg  *  eth0\n",
            "192.0.2.12  0x1  0x2  aabbccddeeff       *  eth0\n",
            "192.0.2.13  0x1  0x2  aa:bb-cc:dd:ee:ff  *  eth0\n",
            "192.0.2.14  0xG  0x2  aa:bb:cc:dd:ee:14  *  eth0\n",
            "192.0.2.15  0x1  0x2  aa:bb:cc:dd:ee:15  not-a-mask  eth0\n",
            "192.0.2.16  0x1  0x2  aa:bb:cc:dd:ee:16  *  eth/0\n",
            "192.0.2.18  0x1  0x2  aa:bb:cc:dd:ee:18  *  eth:0\n",
            "192.0.2.19  0x1  0x2  aa:bb:cc:dd:ee:19  *  aaaaaaaaaaaaaaaa\n",
            "\n",
            "lonely\n",
            "192.0.2.20  0x1  0x2  aa:bb:cc:dd:ee:20  *  eth0\n",
        );
        let entries = neighbors_from_bytes(content.as_bytes(), &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 1]), ip([192, 0, 2, 20])],
            "AC-7: garbage lines are skipped whole, valid anchors still parse"
        );
    }

    #[test]
    fn non_utf8_lines_are_skipped_whole() {
        // Bytes that are not valid UTF-8 decode to U+FFFD; no column
        // accepts that character, so the affected lines are skipped
        // whole while their neighbors parse.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ARP_HEADER.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(b"192.0.2.1  0x1  0x2  aa:bb:cc:dd:ee:01  *  eth0\n");
        bytes.extend_from_slice(b"192.0.2.2  0x1  0x2  a\xff:bb:cc:dd:ee:02  *  eth0\n");
        bytes.extend_from_slice(b"192.0.2\xff.3  0x1  0x2  aa:bb:cc:dd:ee:03  *  eth0\n");
        bytes.extend_from_slice(b"192.0.2.4  0x1  0x2  aa:bb:cc:dd:ee:04  *  eth0\n");
        let entries = neighbors_from_bytes(&bytes, &scope(), "eth0");
        assert_eq!(
            ips(&entries),
            [ip([192, 0, 2, 1]), ip([192, 0, 2, 4])],
            "the lines with 0xff inside the MAC and the IP are dropped"
        );
    }

    #[test]
    fn whitespace_runs_tabs_and_crlf_are_tolerated() {
        // Any run of whitespace separates columns (Appendix E): tabs,
        // multi-space runs, leading whitespace and CRLF endings all
        // parse; the dash-separated MAC form is accepted (R4) and
        // displays canonically; the Mask column may be a dotted netmask.
        let content = concat!(
            "IP address\tHW type\tFlags\tHW address\tMask\tDevice\r\n",
            "\t192.0.2.1\t0x1\t0x2\taa:bb:cc:dd:ee:01\t\t*\teth0 \r\n",
            "  198.51.100.7  0x1  0x6  aa-bb-cc-dd-ee-07  255.255.255.255  wlan0\n",
        );
        let entries = parse_arp_table(content);
        assert_eq!(entries.len(), 2);
        let first = entries.first().expect("tab/CRLF row");
        assert_eq!(first.ip(), ip([192, 0, 2, 1]));
        assert_eq!(first.device(), "eth0");
        let second = entries.get(1).expect("multi-space row");
        assert_eq!(second.mac().to_string(), "aa:bb:cc:dd:ee:07");
        assert_eq!(second.hw_type(), 1);
        assert_eq!(second.flags(), 0x6);
    }

    #[test]
    fn columns_past_the_sixth_are_ignored() {
        // Appendix E: "ignore unknown columns" — a longer line keeps its
        // first six columns and drops the rest (T-101 deviation-4
        // behavior).
        let content = concat!(
            "IP address       HW type     Flags       HW address          Mask   Device\n",
            "192.0.2.1  0x1  0x2  aa:bb:cc:dd:ee:01  *  eth0  EXTRA  0x0  junk\n",
        );
        let entries = parse_arp_table(content);
        assert_eq!(ips(&entries), [ip([192, 0, 2, 1])]);
    }

    #[test]
    fn headerless_input_loses_only_its_first_line() {
        // Appendix E files always carry the header; a headerless (i.e.
        // non-kernel) file still parses from its second line, and the
        // first line is consumed as the header. Documented behavior,
        // same as `parse_routes`.
        let content = concat!(
            "192.0.2.1  0x1  0x2  aa:bb:cc:dd:ee:01  *  eth0\n",
            "192.0.2.2  0x1  0x2  aa:bb:cc:dd:ee:02  *  eth0\n",
        );
        let entries = parse_arp_table(content);
        assert_eq!(ips(&entries), [ip([192, 0, 2, 2])]);
    }

    #[test]
    fn is_complete_reflects_the_atf_com_bit() {
        // (flags, is_complete): bit 0x2 is `ATF_COM`; the raw value is
        // preserved for every other use (R5).
        let table: [(u32, bool); 7] = [
            (0x0, false),
            (0x1, false),
            (0x2, true),
            (0x3, true),
            (0x4, false),
            (0x6, true),
            (0xA, true),
        ];
        for (flags, expected) in table {
            let entry = NeighborEntry {
                ip: ip([192, 0, 2, 1]),
                mac: MacAddr::from_octets([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
                    .expect("valid sender MAC"),
                hw_type: 1,
                flags,
                device: String::from("eth0"),
            };
            assert_eq!(entry.is_complete(), expected, "flags {flags:#x}");
            assert_eq!(entry.flags(), flags, "the raw value is preserved (R5)");
        }
    }

    // ---- bounded read (card §7 AC-8) ---------------------------------------

    #[test]
    fn the_read_is_capped_at_64_kib() {
        // A 1.28 MB table of fixed 64-byte lines: only the lines that
        // lie inside the first 64 KiB can be read, and the exact count
        // proves the cap — the entry count matches the number of
        // complete lines in the first 64 KiB, not the 20,000 in the
        // file.
        // The cap fixture uses the compact tab-separated header (48
        // bytes): line 0 is skipped whatever it contains, and with this
        // header the 64 KiB cut lands 16 bytes into a following line —
        // inside the IP column, where the truncated fragment cannot
        // carry six columns.
        let header = "IP address\tHW type\tFlags\tHW address\tMask\tDevice\n";
        assert_eq!(header.len(), 48, "the fixture header is exactly 48 bytes");
        let line = format!(
            "{:<63}\n",
            "192.0.2.1  0x1  0x2  aa:bb:cc:dd:ee:ff  *  eth0"
        );
        assert_eq!(line.len(), 64, "the fixture line is exactly 64 bytes");

        let total_lines = 20_000;
        let mut content = String::with_capacity(header.len() + total_lines * line.len());
        content.push_str(header);
        for _ in 0..total_lines {
            content.push_str(&line);
        }
        assert!(
            content.len() > 1024 * 1024,
            "the fixture exceeds 1 MB (SR-10 scenario)"
        );

        let cap = usize::try_from(ARP_TABLE_MAX_BYTES).expect("fits usize");
        let remainder = (cap - header.len()) % line.len();
        // The cut must land inside the first columns of the following
        // line, so the truncated fragment cannot carry six columns (the
        // sixth column of this fixture ends at byte offset 47).
        assert!(remainder < 47, "fixture drifted: cut at {remainder} bytes");
        let expected = (cap - header.len()) / line.len();

        let path = std::env::temp_dir().join(format!(
            "osza-netmon-t102-arp-cap-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, content.as_bytes()).expect("temp file is writable");
        let entries = ProcNeighborTable::from_path(&path)
            .read_neighbors(&scope(), "eth0")
            .expect("the bounded read succeeds");
        let _ignored = std::fs::remove_file(&path);

        assert_eq!(
            entries.len(),
            expected,
            "exactly the lines inside the first 64 KiB are returned"
        );
        assert!(entries.len() < total_lines);
        assert!(entries.len() <= cap / line.len());
    }

    // ---- source surface -----------------------------------------------------

    #[test]
    fn constructors_expose_the_documented_paths() {
        let table = ProcNeighborTable::new();
        assert_eq!(table.path(), Path::new("/proc/net/arp"));
        assert_eq!(ProcNeighborTable::default(), table);
        let fixture = ProcNeighborTable::from_path("/tmp/osza-netmon-t102-fixture.arp");
        assert_eq!(
            fixture.path(),
            Path::new("/tmp/osza-netmon-t102-fixture.arp")
        );
    }

    #[test]
    fn unreadable_sources_are_io_errors() {
        let missing = ProcNeighborTable::from_path("/nonexistent/osza-netmon-t102/arp");
        let result = missing.read_neighbors(&scope(), "eth0");
        let error = result.expect_err("the file does not exist");
        assert!(matches!(error, NeighborError::Io { .. }));
        assert!(
            error
                .to_string()
                .contains("/nonexistent/osza-netmon-t102/arp"),
            "the error names the offending path: {error}"
        );
        assert!(std::error::Error::source(&error).is_some());

        // A directory opens but cannot be read as a file.
        let directory = ProcNeighborTable::from_path(std::env::temp_dir());
        assert!(matches!(
            directory.read_neighbors(&scope(), "eth0"),
            Err(NeighborError::Io { .. })
        ));
    }

    #[test]
    fn the_trait_is_object_safe() {
        // R10: the trait must stay object-safe so a `dyn NeighborSource`
        // can hold both this source and the future netlink source.
        let table = ProcNeighborTable::new();
        let source: &dyn NeighborSource = &table;
        // Calling through the object must compile and return quietly;
        // the result depends on the host, the call itself is the point.
        let _ = source.read_neighbors(&scope(), "eth0");
    }

    #[test]
    fn live_kernel_table_satisfies_the_documented_invariants() {
        // Every Linux host exposes /proc/net/arp (the file exists even
        // with an empty table), like T-101's `lo` invariant. The values
        // are host-specific; the invariants are not.
        let table = ProcNeighborTable::new();
        let scope = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid");
        let first = table
            .read_neighbors(&scope, "eth0")
            .expect("the kernel table is readable");
        for entry in &first {
            assert!(entry.is_complete(), "FR-DS-02 completeness filter");
            assert_eq!(entry.device(), "eth0", "FR-DS-02 interface filter");
            assert!(scope.contains(entry.ip()), "FR-DS-02 scope filter");
        }
        // The table is read-only: a second read agrees (a change between
        // the reads would mean the kernel table itself changed, the same
        // accepted flake as T-101's live test).
        let again = table
            .read_neighbors(&scope, "eth0")
            .expect("still readable");
        assert_eq!(first, again, "the kernel table is read-only");
    }

    // ---- property tests (card §6/AC-9: 1,000 hostile inputs) ----------------

    #[test]
    fn property_parse_never_panics_on_hostile_input() {
        // 1,000 strings of random bytes (lossily decoded, exactly as the
        // reader decodes them): the parser and the full FR-DS-02
        // pipeline must return quietly on every one, and the output can
        // never exceed the line count.
        let mut rng = Lcg::seeded(0x7102_0001);
        for _ in 0..1000 {
            let len = rng.next_below(300) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
            let content = String::from_utf8_lossy(&bytes);
            let entries = parse_arp_table(&content);
            let lines = content.lines().count();
            assert!(
                entries.len() <= lines,
                "a parser can never emit more entries than lines"
            );
            let filtered = filter_neighbors(entries, &scope(), "eth0");
            assert!(filtered.len() <= lines);
        }
    }

    #[test]
    fn property_parse_never_panics_on_token_soup() {
        // 1,000 lines of column-shaped garbage: 0..16 tokens, each
        // drawn from plausible column values (valid and invalid IPs,
        // hex words with and without the 0x prefix, MACs in three
        // notations including boundary-invalid ones, masks, device
        // names) or pure junk, joined by random whitespace runs.
        let mut rng = Lcg::seeded(0x7102_0002);
        let junk: [&str; 6] = ["!!", "ZZ", "0x", "-", "ÿ", "###"];
        let spaces: [&str; 3] = [" ", "\t", "  "];
        let ips: [&str; 4] = ["192.0.2.1", "198.51.100.7", "999.0.2.300", "192.0.02.1"];
        let hexes: [&str; 6] = ["0x1", "0x2", "0x0", "0x6", "0xZZ", "2"];
        let macs: [&str; 5] = [
            "aa:bb:cc:dd:ee:ff",
            "02:11:22:33:44:55",
            "aa-bb-cc-dd-ee-ff",
            "aa:bb:cc:dd:ee",
            "00:00:00:00:00:00",
        ];
        let masks: [&str; 3] = ["*", "255.255.255.0", "no-mask"];
        let devices: [&str; 4] = ["eth0", "wlan0", "eth/0", "aaaaaaaaaaaaaaaa"];
        for _ in 0..1000 {
            let columns = rng.next_below(16);
            let mut line = String::new();
            for index in 0..columns {
                if index > 0 {
                    line.push_str(spaces[rng.next_below(spaces.len() as u64) as usize]);
                }
                let token: &str = if rng.next_below(8) == 0 {
                    junk[rng.next_below(junk.len() as u64) as usize]
                } else {
                    match index % 6 {
                        0 => ips[rng.next_below(ips.len() as u64) as usize],
                        1 | 2 => hexes[rng.next_below(hexes.len() as u64) as usize],
                        3 => macs[rng.next_below(macs.len() as u64) as usize],
                        4 => masks[rng.next_below(masks.len() as u64) as usize],
                        _ => devices[rng.next_below(devices.len() as u64) as usize],
                    }
                };
                line.push_str(token);
            }
            let content = format!("{ARP_HEADER}\n{line}\n");
            let entries = parse_arp_table(&content);
            assert!(
                entries.len() <= 1,
                "one data line can yield at most one entry"
            );
        }
    }
}
