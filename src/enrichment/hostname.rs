// SPDX-License-Identifier: GPL-3.0-only

//! Hostname-enrichment configuration and resolver selection (plan §6.5
//! FR-EN-03, §4 ADR-003, task T-203; task-card policy D-1).
//!
//! This module owns everything about *which* resolver is used and *how
//! the worker is tuned*; the DNS wire format lives in [`super::dns`] and
//! the worker thread in [`super::worker`].
//!
//! # Resolver selection (ADR-003 items 1–3, policy D-1)
//!
//! Hostname lookups must go **directly to an eligible local resolver**,
//! never through the libc/NSS resolver. Eligibility is purely
//! subnet-based: of the `nameserver` entries parsed from
//! `/etc/resolv.conf`, an entry is eligible iff it is an IPv4 address
//! **inside the selected subnet**. Because the selected subnet is never
//! a loopback network (plan FR-SC-03), this excludes loopback stubs
//! such as `127.0.0.53` and every IPv6 address by construction.
//!
//! The **fallback**: if `/etc/resolv.conf` parsed at least one
//! `nameserver` entry, none is eligible, *and every* parsed entry is a
//! loopback address (IPv4 `127.0.0.0/8` or IPv6 `::1`) — the signature
//! of a systemd-resolved stub configuration — then the same eligibility
//! rule is applied to the entries of
//! `/run/systemd/resolve/resolv.conf` (when that file exists and is
//! readable). The first eligible entry in file order wins; one resolver
//! per session; **no failover** to any other server, ever.
//!
//! The selection is computed **once per session** by the application
//! (after scope confirmation, in T-205). This module provides the pure
//! function [`select_resolver`] (a total function of arbitrary text)
//! and the thin std wrapper [`select_from_system`] that reads the real
//! files. File reads are size-bounded per SR-10: at most
//! [`RESOLV_CONF_MAX_READ`] bytes (64 KiB) per file are read and the
//! prefix is parsed; unreadable, partially readable or oversize content
//! degrades to "what the prefix parsed", never to a panic.
//!
//! # resolv.conf parsing (policy D-1, plan §7.2 SR-10)
//!
//! [`parse_resolv_conf`] is a total function of arbitrary text: any
//! content yields parsed entries plus counted skips — never an error
//! exit, never a panic. One `nameserver` entry per line: the keyword is
//! matched case-insensitively, surrounding whitespace is tolerated, and
//! the line must carry **exactly one** address token which parses as an
//! IPv4 or IPv6 address. Malformed `nameserver` lines (missing address,
//! extra tokens — a trailing comment makes a line malformed — or an
//! unparseable address) are skipped and counted. Lines whose first
//! token is not `nameserver` (other directives, `#` comments, garbage)
//! are not nameserver lines at all and are ignored without being
//! counted as malformed.
//!
//! # `HostnameConfig` (task-card R-6)
//!
//! [`HostnameConfig`] captures every tunable of the hostname feature
//! with the ADR-003 defaults: 1 s query timeout, 2 attempts (one retry),
//! 5-minute failure backoff, 256-slot command and event queues, 4,096
//! tracked IPs. All values are validated by [`HostnameConfig::try_new`]
//! (non-zero, sane bounds) — nothing is silently clamped (plan §8.7).
//! `enabled: false` is the config knob behind the future
//! `--no-hostnames` flag (T-402).

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use crate::model::Ipv4Net;

/// Path of the primary resolver configuration file (ADR-003 item 2).
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Path of the systemd-resolved configuration consulted only under the
/// loopback-stub fallback rule (ADR-003 item 2).
pub const SYSTEMD_RESOLV_CONF_PATH: &str = "/run/systemd/resolve/resolv.conf";

/// Size bound for one resolver-configuration file read (SR-10): at most
/// 64 KiB per file; the parsed prefix is used when the file is larger.
pub const RESOLV_CONF_MAX_READ: u64 = 64 * 1024;

/// Default `query_timeout` (ADR-003 item 4): 1 second per attempt.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// Default `attempts` (ADR-003 item 4): 2 = the original query plus
/// exactly one retry.
pub const DEFAULT_ATTEMPTS: u8 = 2;

/// Default `failure_backoff` (ADR-003 item 4): a failed IP is not
/// re-queried for 5 minutes.
pub const DEFAULT_FAILURE_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// Default capacity of the command and event queues (task-card R-5:
/// both at least 256).
pub const DEFAULT_QUEUE_CAPACITY: usize = 256;

/// Default tracked-IP cap, matching the registry cap of 4,096
/// (plan NFR-05, ADR-008).
pub const DEFAULT_MAX_TRACKED_IPS: usize = 4096;

/// The port production wiring uses for the selected resolver (the
/// eligibility logic is IP/subnet-based and port-independent; the
/// loopback test passes its own ephemeral port).
pub const DNS_PORT: u16 = 53;

/// Errors rejected by [`HostnameConfig::try_new`]. Wording follows the
/// controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostnameConfigError {
    /// `query_timeout` outside `1 ms..=60 s`.
    #[error("query timeout must be between 1 ms and 60 s, found {found:?}")]
    InvalidQueryTimeout {
        /// The rejected value.
        found: Duration,
    },
    /// `attempts` outside `1..=8`.
    #[error("attempts must be between 1 and 8, found {found}")]
    InvalidAttempts {
        /// The rejected value.
        found: u8,
    },
    /// `failure_backoff` outside `1 ms..=24 h`.
    #[error("failure backoff must be between 1 ms and 24 h, found {found:?}")]
    InvalidFailureBackoff {
        /// The rejected value.
        found: Duration,
    },
    /// `command_capacity` outside `1..=65,536`.
    #[error("command queue capacity must be between 1 and 65,536, found {found}")]
    InvalidCommandCapacity {
        /// The rejected value.
        found: usize,
    },
    /// `event_capacity` outside `1..=65,536`.
    #[error("event queue capacity must be between 1 and 65,536, found {found}")]
    InvalidEventCapacity {
        /// The rejected value.
        found: usize,
    },
    /// `max_tracked_ips` outside `1..=65,536`.
    #[error("tracked-IP cap must be between 1 and 65,536, found {found}")]
    InvalidMaxTrackedIps {
        /// The rejected value.
        found: usize,
    },
}

/// Tuning parameters of the hostname feature, with the ADR-003 defaults
/// (task-card R-6).
///
/// A config is only accepted by [`HostnameConfig::try_new`] after
/// validation — an out-of-range value is a typed
/// [`HostnameConfigError`] instead of a silently clamped one (plan
/// §8.7). [`Default`] yields exactly the ADR-003 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostnameConfig {
    /// Whether the hostname feature runs at all (`false` is the knob
    /// behind `--no-hostnames`, T-402). Default `true`.
    pub enabled: bool,
    /// Wall budget for one resolver attempt (the worker applies
    /// `attempts` of them per lookup). Default 1 s; 1 ms..=60 s.
    pub query_timeout: Duration,
    /// Total attempts per lookup, original query included (2 = one
    /// retry, ADR-003 item 4). Default 2; 1..=8.
    pub attempts: u8,
    /// How long a failed IP stays in backoff before it may be queried
    /// again (ADR-003 item 4). Default 5 min; 1 ms..=24 h.
    pub failure_backoff: Duration,
    /// Capacity of the bounded command channel (worker input).
    /// Default 256; 1..=65,536.
    pub command_capacity: usize,
    /// Capacity of the bounded event channel (worker output).
    /// Default 256; 1..=65,536.
    pub event_capacity: usize,
    /// How many distinct IPs the worker may track (session state cap,
    /// matching the registry cap). Default 4,096; 1..=65,536.
    pub max_tracked_ips: usize,
}

impl Default for HostnameConfig {
    /// The ADR-003 values: enabled, 1 s timeout, 2 attempts, 5-minute
    /// backoff, 256/256 queue slots, 4,096 tracked IPs.
    fn default() -> Self {
        HostnameConfig {
            enabled: true,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            failure_backoff: DEFAULT_FAILURE_BACKOFF,
            command_capacity: DEFAULT_QUEUE_CAPACITY,
            event_capacity: DEFAULT_QUEUE_CAPACITY,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }
}

impl HostnameConfig {
    /// Builds and validates a config from its seven parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use osza_netmon::enrichment::hostname::{HostnameConfig, HostnameConfigError};
    ///
    /// let config = HostnameConfig::try_new(
    ///     true, Duration::from_secs(1), 2, Duration::from_secs(300),
    ///     256, 256, 4096,
    /// )
    /// .expect("the ADR-003 defaults are valid");
    /// assert_eq!(config, HostnameConfig::default());
    ///
    /// assert_eq!(
    ///     HostnameConfig::try_new(
    ///         true, Duration::ZERO, 2, Duration::from_secs(300),
    ///         256, 256, 4096,
    ///     )
    ///     .unwrap_err(),
    ///     HostnameConfigError::InvalidQueryTimeout { found: Duration::ZERO },
    /// );
    /// ```
    pub fn try_new(
        enabled: bool,
        query_timeout: Duration,
        attempts: u8,
        failure_backoff: Duration,
        command_capacity: usize,
        event_capacity: usize,
        max_tracked_ips: usize,
    ) -> Result<Self, HostnameConfigError> {
        let config = HostnameConfig {
            enabled,
            query_timeout,
            attempts,
            failure_backoff,
            command_capacity,
            event_capacity,
            max_tracked_ips,
        };
        config.validate()?;
        Ok(config)
    }

    /// Rejects out-of-range values, reporting the first violation.
    fn validate(&self) -> Result<(), HostnameConfigError> {
        if self.query_timeout.is_zero() || self.query_timeout > Duration::from_secs(60) {
            return Err(HostnameConfigError::InvalidQueryTimeout {
                found: self.query_timeout,
            });
        }
        if self.attempts == 0 || self.attempts > 8 {
            return Err(HostnameConfigError::InvalidAttempts {
                found: self.attempts,
            });
        }
        if self.failure_backoff.is_zero()
            || self.failure_backoff > Duration::from_secs(24 * 60 * 60)
        {
            return Err(HostnameConfigError::InvalidFailureBackoff {
                found: self.failure_backoff,
            });
        }
        if self.command_capacity == 0 || self.command_capacity > 65_536 {
            return Err(HostnameConfigError::InvalidCommandCapacity {
                found: self.command_capacity,
            });
        }
        if self.event_capacity == 0 || self.event_capacity > 65_536 {
            return Err(HostnameConfigError::InvalidEventCapacity {
                found: self.event_capacity,
            });
        }
        if self.max_tracked_ips == 0 || self.max_tracked_ips > 65_536 {
            return Err(HostnameConfigError::InvalidMaxTrackedIps {
                found: self.max_tracked_ips,
            });
        }
        Ok(())
    }
}

/// The `nameserver` entries parsed from one resolver-configuration
/// file, plus the count of malformed `nameserver` lines (policy D-1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvConf {
    /// Parsed `nameserver` addresses, in file order (IPv4 and IPv6).
    pub nameservers: Vec<IpAddr>,
    /// Lines that looked like `nameserver` entries but failed the
    /// exactly-one-address-token rule (missing or extra tokens, or an
    /// unparseable address).
    pub skipped_malformed: usize,
}

/// Parses `nameserver` entries from arbitrary text (policy D-1, plan
/// §7.2 SR-10).
///
/// A total function: any input yields entries plus counted skips,
/// never an error and never a panic. See the module documentation for
/// the exact line grammar.
pub fn parse_resolv_conf(text: &str) -> ResolvConf {
    let mut nameservers = Vec::new();
    let mut skipped_malformed = 0usize;
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        let Some(keyword) = tokens.next() else {
            continue; // empty line: not a nameserver line
        };
        if !keyword.eq_ignore_ascii_case("nameserver") {
            continue; // another directive or a comment line
        }
        let address = tokens.next();
        let extra = tokens.next();
        match (address, extra) {
            (Some(token), None) => match token.parse::<IpAddr>() {
                Ok(addr) => nameservers.push(addr),
                Err(_) => skipped_malformed += 1,
            },
            _ => skipped_malformed += 1,
        }
    }
    ResolvConf {
        nameservers,
        skipped_malformed,
    }
}

/// The outcome of the resolver selection (ADR-003 items 1–3).
///
/// `Selected` carries the address the UI will show as "reverse DNS via
/// `<addr>`" (T-304); `NoResolver` means the hostname feature must
/// answer `Field::Unavailable(Reason::NoResolver)` and **no query is
/// ever sent** (ADR-003 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverSelection {
    /// The first eligible nameserver address.
    Selected {
        /// The selected resolver's IPv4 address.
        address: Ipv4Addr,
        /// `true` when the address came from the systemd-resolved file
        /// via the loopback-stub fallback rather than from
        /// `/etc/resolv.conf`.
        via_systemd_fallback: bool,
    },
    /// No eligible resolver; the feature is unavailable this session.
    NoResolver,
}

impl ResolverSelection {
    /// The selected resolver address, if any.
    pub fn address(&self) -> Option<Ipv4Addr> {
        match self {
            ResolverSelection::Selected { address, .. } => Some(*address),
            ResolverSelection::NoResolver => None,
        }
    }

    /// Whether the selection came from the systemd-resolved fallback
    /// file.
    pub fn via_systemd_fallback(&self) -> bool {
        matches!(
            self,
            ResolverSelection::Selected {
                via_systemd_fallback: true,
                ..
            }
        )
    }

    /// The selected resolver as a socket address on port 53 — the
    /// production wiring for [`super::dns::UdpResolver::new`] (T-205).
    pub fn resolver_socket(&self) -> Option<SocketAddr> {
        self.address()
            .map(|address| SocketAddr::new(IpAddr::V4(address), DNS_PORT))
    }
}

/// The pure resolver-selection core (ADR-003 items 1–3, policy D-1).
///
/// * `etc_text` — the (possibly truncated, possibly garbage) text of
///   `/etc/resolv.conf`.
/// * `systemd_text` — the text of
///   `/run/systemd/resolve/resolv.conf`, or `None` when that file does
///   not exist or was not readable.
/// * `subnet` — the selected subnet; the selected subnet is never
///   loopback (plan FR-SC-03), which is what makes the eligibility
///   rule exclude stubs.
///
/// First eligible IPv4 address in file order wins; the systemd file is
/// consulted only when `/etc/resolv.conf` parsed at least one entry,
/// none is eligible, and every parsed entry is loopback.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use osza_netmon::enrichment::hostname::{ResolverSelection, select_resolver};
/// use osza_netmon::model::Ipv4Net;
///
/// let subnet = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).expect("valid");
/// let stub = "nameserver 127.0.0.53\n".to_owned();
///
/// // A loopback stub alone is never eligible (the subnet is not loopback).
/// assert_eq!(select_resolver(&stub, None, subnet), ResolverSelection::NoResolver);
///
/// // …but with the systemd-resolved file present, its in-subnet entry
/// // is selected under the same rule.
/// let systemd = "nameserver 192.168.1.1\n".to_owned();
/// assert_eq!(
///     select_resolver(&stub, Some(&systemd), subnet),
///     ResolverSelection::Selected {
///         address: Ipv4Addr::new(192, 168, 1, 1),
///         via_systemd_fallback: true,
///     },
/// );
/// ```
pub fn select_resolver(
    etc_text: &str,
    systemd_text: Option<&str>,
    subnet: Ipv4Net,
) -> ResolverSelection {
    let etc = parse_resolv_conf(etc_text);
    if let Some(address) = first_eligible(&etc.nameservers, subnet) {
        return ResolverSelection::Selected {
            address,
            via_systemd_fallback: false,
        };
    }
    // Fallback (ADR-003 item 2): only when at least one nameserver was
    // parsed and every parsed entry is a loopback address — and only
    // when the systemd file exists and was readable.
    let all_loopback =
        !etc.nameservers.is_empty() && etc.nameservers.iter().all(|ip| ip.is_loopback());
    if all_loopback && let Some(text) = systemd_text {
        let systemd = parse_resolv_conf(text);
        if let Some(address) = first_eligible(&systemd.nameservers, subnet) {
            return ResolverSelection::Selected {
                address,
                via_systemd_fallback: true,
            };
        }
    }
    ResolverSelection::NoResolver
}

/// The first IPv4 address in `nameservers` that lies inside `subnet`.
fn first_eligible(nameservers: &[IpAddr], subnet: Ipv4Net) -> Option<Ipv4Addr> {
    nameservers.iter().find_map(|ip| match ip {
        IpAddr::V4(address) if subnet.contains(*address) => Some(*address),
        _ => None,
    })
}

/// Reads at most [`RESOLV_CONF_MAX_READ`] bytes of `path` as text
/// (lossily decoded), for the total, size-bounded wrapper (SR-10).
///
/// `None` only when the file cannot be opened at all. A read error
/// mid-file keeps the bytes read so far (std `read_to_end` semantics);
/// invalid UTF-8 degrades via lossy conversion; a file larger than the
/// bound is cut at the bound. The result never depends on, and never
/// panics on, file content.
pub fn read_bounded(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    // Errors keep the prefix that was read: the caller parses what the
    // prefix yielded (SR-10, "degrades to what the prefix parsed").
    let _ = file.take(RESOLV_CONF_MAX_READ).read_to_end(&mut bytes);
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The std wrapper: selects the session resolver from the real
/// `/etc/resolv.conf` and — under the fallback rule — the real
/// systemd-resolved file (T-205 calls this once after scope
/// confirmation).
///
/// Both files are read with the SR-10 size bound; missing or unreadable
/// files degrade to empty text (`None`), which the pure core treats as
/// "no entries from that source".
pub fn select_from_system(subnet: Ipv4Net) -> ResolverSelection {
    let etc = read_bounded(Path::new(RESOLV_CONF_PATH));
    let systemd = read_bounded(Path::new(SYSTEMD_RESOLV_CONF_PATH));
    select_resolver(etc.as_deref().unwrap_or(""), systemd.as_deref(), subnet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn subnet_192() -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 100), 24).expect("valid subnet")
    }

    // ---- parse_resolv_conf: the line grammar ----------------------------------------

    #[test]
    fn parses_nameserver_entries_in_order() {
        let text = "nameserver 192.168.1.1\nnameserver 10.0.0.53\n";
        let parsed = parse_resolv_conf(text);
        assert_eq!(
            parsed.nameservers,
            vec![v4(192, 168, 1, 1), v4(10, 0, 0, 53)]
        );
        assert_eq!(parsed.skipped_malformed, 0);
    }

    #[test]
    fn keyword_is_case_insensitive_and_whitespace_tolerant() {
        let text = "  NAMEServer\t192.168.1.1  \n\tNameServer   10.0.0.53\t\n";
        let parsed = parse_resolv_conf(text);
        assert_eq!(
            parsed.nameservers,
            vec![v4(192, 168, 1, 1), v4(10, 0, 0, 53)]
        );
        assert_eq!(parsed.skipped_malformed, 0);
    }

    #[test]
    fn parses_ipv6_entries_too() {
        let text = "nameserver fd00::1\nnameserver ::1\n";
        let parsed = parse_resolv_conf(text);
        assert_eq!(
            parsed.nameservers,
            vec![
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST), // ::1
            ]
        );
    }

    #[test]
    fn malformed_nameserver_lines_are_skipped_and_counted() {
        let text = concat!(
            "nameserver\n",                   // missing address
            "nameserver 192.168.1.1 extra\n", // trailing comment = extra token
            "nameserver not-an-address\n",    // unparseable address
            "nameserver 1.2.3.4 5.6.7.8\n",   // two addresses
            "nameserver 192.168.1.1\n",       // valid
        );
        let parsed = parse_resolv_conf(text);
        assert_eq!(parsed.nameservers, vec![v4(192, 168, 1, 1)]);
        assert_eq!(parsed.skipped_malformed, 4);
    }

    #[test]
    fn non_nameserver_lines_are_ignored_without_counting() {
        let text = concat!(
            "# a comment mentioning nameserver 192.168.1.1\n",
            "#nameserver 10.0.0.1\n",
            "search example.lan\n",
            "domain example.lan\n",
            "options timeout:2\n",
            "\n",
            "   \t\n",
            "garbage \u{0} bytes \u{1b}[31m\n",
            "NAMESERVERX 10.0.0.1\n", // keyword must match exactly (ci), not by prefix
        );
        let parsed = parse_resolv_conf(text);
        assert!(parsed.nameservers.is_empty());
        assert_eq!(parsed.skipped_malformed, 0);
    }

    #[test]
    fn empty_and_hostile_input_yield_empty_parses() {
        for text in ["", "\n\n\n", "\u{0}\u{0}\u{0}", "nameserver \u{0}"] {
            let parsed = parse_resolv_conf(text);
            assert!(parsed.nameservers.is_empty(), "input: {text:?}");
        }
        // "nameserver \u{0}" — a single unparseable token: counted.
        assert_eq!(parse_resolv_conf("nameserver \u{0}").skipped_malformed, 1);
    }

    #[test]
    fn crlf_line_endings_are_tolerated() {
        let text = "nameserver 192.168.1.1\r\nnameserver 10.0.0.53\r\n";
        let parsed = parse_resolv_conf(text);
        assert_eq!(
            parsed.nameservers,
            vec![v4(192, 168, 1, 1), v4(10, 0, 0, 53)]
        );
        assert_eq!(parsed.skipped_malformed, 0);
    }

    // ---- property tests (AC-3) --------------------------------------------------------

    /// Property: arbitrary text never panics, and the totals invariant
    /// holds — the number of lines whose first token is `nameserver`
    /// (case-insensitive) equals entries plus counted skips.
    #[test]
    fn property_parser_is_total_and_totals_hold() {
        const ALPHABET: [char; 24] = [
            'n', 'N', 'a', 'A', 'm', 'e', 's', 'r', 'v', 'e', '2', '0', '.', '1', '9', ':', ' ',
            '\t', '\n', '#', '\u{0}', 'x', '6', '-',
        ];
        // Spliced lines: realistic and hostile nameserver lines so the
        // entry paths are exercised (pure random text essentially never
        // spells "nameserver" + a valid address).
        const SPLICE: [&str; 9] = [
            "nameserver 192.168.1.1",
            "  NameServer\t10.0.0.53  ",
            "nameserver fd00::1",
            "nameserver ::1",
            "nameserver",
            "nameserver bogus.example",
            "nameserver 1.2.3.4 trailing comment",
            "search example.lan",
            "# nameserver 127.0.0.53",
        ];
        let mut rng = Lcg::seeded(0xE0_53_00_01);
        let mut exercised_entries = 0usize;
        for round in 0..2000 {
            let len = rng.next_below(300) as usize;
            let mut text = String::new();
            for _ in 0..len {
                // Every 30th character position starts a spliced line
                // instead of a random one.
                if round % 2 == 0 && rng.next_below(30) == 0 {
                    let index = rng.next_below(SPLICE.len() as u64) as usize;
                    if let Some(line) = SPLICE.get(index) {
                        text.push_str(line);
                    }
                    text.push('\n');
                } else {
                    let index = rng.next_below(ALPHABET.len() as u64) as usize;
                    if let Some(c) = ALPHABET.get(index) {
                        text.push(*c);
                    }
                }
            }
            let parsed = parse_resolv_conf(&text);
            // The totals invariant, re-derived independently.
            let nameserver_lines = text
                .lines()
                .filter(|line| {
                    line.split_whitespace()
                        .next()
                        .is_some_and(|first| first.eq_ignore_ascii_case("nameserver"))
                })
                .count();
            assert_eq!(
                parsed.nameservers.len() + parsed.skipped_malformed,
                nameserver_lines,
                "input: {text:?}"
            );
            // Every entry parses back as an address (by construction).
            for ip in &parsed.nameservers {
                assert_eq!(Some(ip), ip.to_string().parse::<IpAddr>().ok().as_ref());
            }
            exercised_entries += parsed.nameservers.len();
        }
        // Non-vacuity: the alphabet can spell nameserver lines, and some
        // inputs must produce entries.
        assert!(exercised_entries > 0, "no entries parsed in 2000 inputs");
    }

    /// Property: arbitrary bytes (lossily decoded) never panic the
    /// parser, and selection over them stays total.
    #[test]
    fn property_arbitrary_bytes_never_panic() {
        let mut rng = Lcg::seeded(0xE0_53_00_02);
        for _ in 0..2000 {
            let len = rng.next_below(512) as usize;
            let mut bytes = Vec::new();
            for _ in 0..len {
                bytes.push(rng.next_u8());
            }
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_resolv_conf(&text);
            let _ = select_resolver(&text, Some(&text), subnet_192());
        }
    }

    /// Property: a selection is never an address outside the subnet,
    /// and a `Selected` address always came from the input.
    #[test]
    fn property_selection_stays_inside_the_subnet() {
        const TOKENS: [&str; 10] = [
            "nameserver",
            "192.168.1.1",
            "10.0.0.53",
            "127.0.0.53",
            "fd00::1",
            "\n",
            " ",
            "#",
            "junk",
            "nameserver",
        ];
        let subnet = subnet_192();
        let mut rng = Lcg::seeded(0xE0_53_00_03);
        let mut selected_count = 0usize;
        for _ in 0..2000 {
            let lines = rng.next_below(12);
            let mut text = String::new();
            for _ in 0..lines {
                let tokens = 1 + rng.next_below(4) as usize;
                for t in 0..tokens {
                    if t > 0 {
                        text.push(' ');
                    }
                    text.push_str(TOKENS[rng.next_below(TOKENS.len() as u64) as usize]);
                }
                text.push('\n');
            }
            if let ResolverSelection::Selected { address, .. } =
                select_resolver(&text, None, subnet)
            {
                assert!(
                    subnet.contains(address),
                    "selected {address} outside {subnet:?}"
                );
                selected_count += 1;
            }
        }
        assert!(selected_count > 0, "no selection exercised");
    }

    // ---- resolver selection (AC-2) ----------------------------------------------------

    #[test]
    fn in_subnet_entry_is_selected() {
        let text = "nameserver 192.168.1.53\n";
        assert_eq!(
            select_resolver(text, None, subnet_192()),
            ResolverSelection::Selected {
                address: Ipv4Addr::new(192, 168, 1, 53),
                via_systemd_fallback: false,
            }
        );
    }

    #[test]
    fn off_subnet_entry_is_rejected() {
        let text = "nameserver 10.0.0.1\nnameserver 192.168.2.1\n";
        assert_eq!(
            select_resolver(text, None, subnet_192()),
            ResolverSelection::NoResolver
        );
    }

    #[test]
    fn loopback_stub_is_rejected() {
        // 127.0.0.53 is loopback; the selected subnet is never loopback
        // (FR-SC-03), so the stub can never be eligible. With no systemd
        // file the answer is NoResolver — and no query is ever sent.
        let text = "nameserver 127.0.0.53\n";
        assert_eq!(
            select_resolver(text, None, subnet_192()),
            ResolverSelection::NoResolver
        );
        // The same holds with a systemd file that has nothing eligible.
        let systemd = "nameserver 10.0.0.1\n";
        assert_eq!(
            select_resolver(text, Some(systemd), subnet_192()),
            ResolverSelection::NoResolver
        );
    }

    #[test]
    fn ipv6_entries_are_never_eligible() {
        let text = "nameserver fd00::53\nnameserver fe80::1\n";
        assert_eq!(
            select_resolver(text, None, subnet_192()),
            ResolverSelection::NoResolver
        );
    }

    #[test]
    fn first_in_file_order_wins() {
        let text = "nameserver 192.168.1.10\nnameserver 192.168.1.20\n";
        assert_eq!(
            select_resolver(text, None, subnet_192()).address(),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        // The fallback file follows the same first-in-order rule.
        let stub = "nameserver 127.0.0.53\n";
        let systemd = "nameserver 192.168.1.20\nnameserver 192.168.1.10\n";
        assert_eq!(
            select_resolver(stub, Some(systemd), subnet_192()).address(),
            Some(Ipv4Addr::new(192, 168, 1, 20))
        );
    }

    #[test]
    fn systemd_fallback_requires_every_parsed_entry_to_be_loopback() {
        let stub = "nameserver 127.0.0.53\n";
        let systemd_with_eligible = "nameserver 192.168.1.9\n";
        // All-loopback /etc/resolv.conf + fallback file with an eligible
        // entry → selected via fallback.
        assert_eq!(
            select_resolver(stub, Some(systemd_with_eligible), subnet_192()),
            ResolverSelection::Selected {
                address: Ipv4Addr::new(192, 168, 1, 9),
                via_systemd_fallback: true,
            }
        );

        // One non-loopback entry (even an off-subnet one) blocks the
        // fallback: the systemd file is not consulted at all.
        let mixed = "nameserver 127.0.0.53\nnameserver 8.8.8.8\n";
        assert_eq!(
            select_resolver(mixed, Some(systemd_with_eligible), subnet_192()),
            ResolverSelection::NoResolver
        );

        // An IPv6 loopback entry (::1) still counts as loopback for the
        // fallback condition.
        let stub_v6 = "nameserver ::1\n";
        assert_eq!(
            select_resolver(stub_v6, Some(systemd_with_eligible), subnet_192()),
            ResolverSelection::Selected {
                address: Ipv4Addr::new(192, 168, 1, 9),
                via_systemd_fallback: true,
            }
        );

        // No nameserver entries at all (empty file) → no fallback.
        assert_eq!(
            select_resolver("", Some(systemd_with_eligible), subnet_192()),
            ResolverSelection::NoResolver
        );

        // All entries malformed → nothing parsed → no fallback.
        let all_malformed = "nameserver\nnameserver bogus\n";
        assert_eq!(
            select_resolver(all_malformed, Some(systemd_with_eligible), subnet_192()),
            ResolverSelection::NoResolver
        );
    }

    #[test]
    fn fallback_entries_follow_the_same_subnet_rule() {
        let stub = "nameserver 127.0.0.53\n";
        // The fallback file's only entry is off-subnet → NoResolver.
        let systemd = "nameserver 10.0.0.1\n";
        assert_eq!(
            select_resolver(stub, Some(systemd), subnet_192()),
            ResolverSelection::NoResolver
        );
        // …and a loopback entry in the fallback file is equally ineligible.
        let systemd_stub = "nameserver 127.0.0.53\n";
        assert_eq!(
            select_resolver(stub, Some(systemd_stub), subnet_192()),
            ResolverSelection::NoResolver
        );
    }

    #[test]
    fn no_eligible_entry_yields_no_resolver() {
        for text in ["", "# empty\n", "nameserver bogus\n", "options edns0\n"] {
            assert_eq!(
                select_resolver(text, None, subnet_192()),
                ResolverSelection::NoResolver,
                "input: {text:?}"
            );
        }
    }

    #[test]
    fn garbage_and_oversize_input_degrade_to_no_resolver() {
        let mut rng = Lcg::seeded(0xE0_53_00_04);
        let mut garbage = String::new();
        for _ in 0..4096 {
            garbage.push(rng.next_u8() as char);
        }
        assert_eq!(
            select_resolver(&garbage, Some(&garbage), subnet_192()),
            ResolverSelection::NoResolver
        );
        // Oversize (beyond the read bound) with an eligible entry AFTER
        // the cut: the prefix parses, and nothing past 64 KiB is seen —
        // the pure function simply never receives the trailing bytes.
        let mut oversize = "#".repeat(RESOLV_CONF_MAX_READ as usize + 1024);
        oversize.push('\n');
        oversize.push_str("nameserver 192.168.1.53\n");
        let prefix = oversize
            .get(..RESOLV_CONF_MAX_READ as usize)
            .expect("in-bounds");
        assert_eq!(
            select_resolver(prefix, None, subnet_192()),
            ResolverSelection::NoResolver
        );
        // …while the same text fully parsed (as the wrapper would present
        // it if the entry were inside the bound) selects.
        assert_eq!(
            select_resolver(&oversize, None, subnet_192()).address(),
            Some(Ipv4Addr::new(192, 168, 1, 53))
        );
    }

    // ---- read_bounded (SR-10) ---------------------------------------------------------

    /// A unique-enough temp path for one test run.
    fn temp_path(tag: u32) -> std::path::PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("osza-t203-resolv-{pid}-{tag}-{n}.conf"))
    }

    #[test]
    fn read_bounded_returns_file_content() {
        let path = temp_path(1);
        std::fs::write(&path, b"nameserver 192.168.1.53\n").expect("write temp file");
        let text = read_bounded(&path).expect("readable");
        assert_eq!(text, "nameserver 192.168.1.53\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_bounded_is_none_for_missing_files() {
        let path = temp_path(2);
        assert_eq!(read_bounded(&path), None);
    }

    #[test]
    fn read_bounded_cuts_oversize_files_at_the_bound() {
        let path = temp_path(3);
        // 64 KiB of comment padding, then the eligible entry past the cut.
        let mut content = vec![b'#'; RESOLV_CONF_MAX_READ as usize];
        content.extend_from_slice(b"nameserver 192.168.1.53\n");
        std::fs::write(&path, &content).expect("write temp file");
        let text = read_bounded(&path).expect("readable");
        assert_eq!(text.len(), RESOLV_CONF_MAX_READ as usize);
        assert!(!text.contains("nameserver"));
        // What the wrapper would parse from that prefix: no entry.
        assert_eq!(
            select_resolver(&text, None, subnet_192()),
            ResolverSelection::NoResolver
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_bounded_degrades_invalid_utf8_lossily() {
        let path = temp_path(4);
        std::fs::write(&path, b"nameserver 192.168.1.53\n\xff\xfe garbage\n")
            .expect("write temp file");
        let text = read_bounded(&path).expect("readable");
        // The valid line parses; the invalid bytes degrade, not fail.
        assert_eq!(
            select_resolver(&text, None, subnet_192()).address(),
            Some(Ipv4Addr::new(192, 168, 1, 53))
        );
        let _ = std::fs::remove_file(&path);
    }

    // ---- selection helpers ------------------------------------------------------------

    #[test]
    fn selection_helpers_expose_address_and_socket() {
        let selected = ResolverSelection::Selected {
            address: Ipv4Addr::new(192, 168, 1, 53),
            via_systemd_fallback: true,
        };
        assert_eq!(selected.address(), Some(Ipv4Addr::new(192, 168, 1, 53)));
        assert!(selected.via_systemd_fallback());
        assert_eq!(
            selected.resolver_socket().map(|s| s.to_string()),
            Some("192.168.1.53:53".to_owned())
        );
        assert_eq!(ResolverSelection::NoResolver.address(), None);
        assert_eq!(ResolverSelection::NoResolver.resolver_socket(), None);
        assert!(!ResolverSelection::NoResolver.via_systemd_fallback());
    }

    // ---- HostnameConfig (R-6) ----------------------------------------------------------

    #[test]
    fn defaults_are_the_adr_003_values() {
        let config = HostnameConfig::default();
        assert!(config.enabled);
        assert_eq!(config.query_timeout, Duration::from_secs(1));
        assert_eq!(config.attempts, 2);
        assert_eq!(config.failure_backoff, Duration::from_secs(5 * 60));
        assert_eq!(config.command_capacity, 256);
        assert_eq!(config.event_capacity, 256);
        assert_eq!(config.max_tracked_ips, 4096);
        // try_new with the same values round-trips to the default.
        assert_eq!(
            HostnameConfig::try_new(
                true,
                Duration::from_secs(1),
                2,
                Duration::from_secs(300),
                256,
                256,
                4096
            )
            .expect("defaults valid"),
            config
        );
    }

    #[test]
    fn try_new_rejects_every_out_of_range_value() {
        let valid = |timeout: Duration,
                     attempts: u8,
                     backoff: Duration,
                     cmd: usize,
                     ev: usize,
                     ips: usize| {
            HostnameConfig::try_new(true, timeout, attempts, backoff, cmd, ev, ips)
        };
        assert_eq!(
            valid(Duration::ZERO, 2, Duration::from_secs(300), 256, 256, 4096).unwrap_err(),
            HostnameConfigError::InvalidQueryTimeout {
                found: Duration::ZERO
            }
        );
        assert_eq!(
            valid(
                Duration::from_secs(61),
                2,
                Duration::from_secs(300),
                256,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidQueryTimeout {
                found: Duration::from_secs(61)
            }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                0,
                Duration::from_secs(300),
                256,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidAttempts { found: 0 }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                9,
                Duration::from_secs(300),
                256,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidAttempts { found: 9 }
        );
        assert_eq!(
            valid(Duration::from_secs(1), 2, Duration::ZERO, 256, 256, 4096).unwrap_err(),
            HostnameConfigError::InvalidFailureBackoff {
                found: Duration::ZERO
            }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                2,
                Duration::from_secs(24 * 60 * 60 + 1),
                256,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidFailureBackoff {
                found: Duration::from_secs(24 * 60 * 60 + 1)
            }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                2,
                Duration::from_secs(300),
                0,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidCommandCapacity { found: 0 }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                2,
                Duration::from_secs(300),
                65_537,
                256,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidCommandCapacity { found: 65_537 }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                2,
                Duration::from_secs(300),
                256,
                0,
                4096
            )
            .unwrap_err(),
            HostnameConfigError::InvalidEventCapacity { found: 0 }
        );
        assert_eq!(
            valid(
                Duration::from_secs(1),
                2,
                Duration::from_secs(300),
                256,
                256,
                0
            )
            .unwrap_err(),
            HostnameConfigError::InvalidMaxTrackedIps { found: 0 }
        );
    }

    #[test]
    fn try_new_accepts_the_range_boundaries() {
        // Every bound is inclusive at both ends (non-zero, sane bounds).
        HostnameConfig::try_new(
            false,
            Duration::from_millis(1),
            1,
            Duration::from_millis(1),
            1,
            1,
            1,
        )
        .expect("lower bounds valid");
        HostnameConfig::try_new(
            true,
            Duration::from_secs(60),
            8,
            Duration::from_secs(24 * 60 * 60),
            65_536,
            65_536,
            65_536,
        )
        .expect("upper bounds valid");
    }

    // ---- controlled vocabulary (§5.4 / §11.7) -------------------------------------------

    /// Every string this module can surface (config error `Display`
    /// forms) stays inside plan §5.4's controlled vocabulary.
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
            HostnameConfigError::InvalidQueryTimeout {
                found: Duration::ZERO,
            }
            .to_string(),
            HostnameConfigError::InvalidAttempts { found: 0 }.to_string(),
            HostnameConfigError::InvalidFailureBackoff {
                found: Duration::ZERO,
            }
            .to_string(),
            HostnameConfigError::InvalidCommandCapacity { found: 0 }.to_string(),
            HostnameConfigError::InvalidEventCapacity { found: 0 }.to_string(),
            HostnameConfigError::InvalidMaxTrackedIps { found: 0 }.to_string(),
        ];
        for text in &texts {
            for banned in BANNED {
                assert!(
                    !text.to_lowercase().contains(banned),
                    "banned word {banned:?} in: {text}"
                );
            }
        }
    }
}
