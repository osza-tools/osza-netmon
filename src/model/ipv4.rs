// SPDX-License-Identifier: GPL-3.0-only

//! IPv4 classification helpers and subnet math: [`Ipv4Net`] and the
//! private / link-local / CGNAT predicates (plan §5.2, FR-SC-05/06/07,
//! Appendix E, task T-002).
//!
//! Classification follows Appendix E exactly: RFC 1918
//! (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local
//! (`169.254.0.0/16`) and CGNAT (`100.64.0.0/10`, RFC 6598). Host-range
//! math implements FR-SC-05: the network and broadcast addresses are not
//! usable hosts for prefixes up to /30; `/31` (RFC 3021) uses both
//! addresses; `/32` is a single host. Capacity follows FR-SC-06: the
//! default active-scan cap is 1,022 hosts (/22) and the absolute ceiling
//! is 65,534 (/16).
//!
//! All functions are total: no panics, no indexing, arithmetic by
//! construction in-range (plan SR-02).

use std::convert::TryFrom;
use std::fmt;
use std::net::Ipv4Addr;

/// Default active-scan host cap: **1,022 hosts (/22)** (FR-SC-06).
pub const DEFAULT_MAX_HOSTS: u32 = 1022;

/// Absolute host-cap ceiling: **65,534 hosts (/16)** (FR-SC-06); larger
/// values are rejected outright, `--max-hosts` cannot exceed it.
pub const ABSOLUTE_MAX_HOSTS: u32 = 65_534;

/// `true` for RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`,
/// `192.168.0.0/16`).
pub fn is_private(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    (bits & 0xff00_0000) == 0x0a00_0000        // 10.0.0.0/8
        || (bits & 0xfff0_0000) == 0xac10_0000 // 172.16.0.0/12
        || (bits & 0xffff_0000) == 0xc0a8_0000 // 192.168.0.0/16
}

/// `true` for IPv4 link-local addresses (`169.254.0.0/16`, RFC 3927).
pub fn is_link_local(ip: Ipv4Addr) -> bool {
    (u32::from(ip) & 0xffff_0000) == 0xa9fe_0000
}

/// `true` for carrier-grade NAT addresses (`100.64.0.0/10`, RFC 6598).
pub fn is_cgnat(ip: Ipv4Addr) -> bool {
    (u32::from(ip) & 0xffc0_0000) == 0x6440_0000
}

/// A validated IPv4 network in CIDR form (plan §5.2: "own small
/// `Ipv4Net`").
///
/// The stored address is always the network base: host bits given to
/// [`new`](Ipv4Net::new) are masked off, so `Ipv4Net::new(a, p)` and
/// `Ipv4Net::new(b, p)` describe the same network whenever `a` and `b`
/// lie inside it. The prefix length is validated (`0..=32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    network: Ipv4Addr,
    prefix_len: u8,
}

/// Errors returned by [`Ipv4Net`] constructors and host-range math.
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Ipv4NetError {
    /// The prefix length is outside `0..=32`.
    #[error("invalid prefix length: expected 0..=32, found {found}")]
    InvalidPrefix {
        /// The rejected prefix length.
        found: u8,
    },
    /// The requested cap exceeds [`ABSOLUTE_MAX_HOSTS`].
    #[error("host cap {found} exceeds the absolute ceiling of {max}")]
    InvalidMaxHosts {
        /// The rejected cap.
        found: u32,
        /// The absolute ceiling (65,534).
        max: u32,
    },
    /// The network's usable host count exceeds the applicable cap
    /// (FR-SC-06).
    #[error("network has {requested} usable hosts, above the cap of {cap}")]
    OverCapacity {
        /// Usable hosts in the network.
        requested: u32,
        /// The cap that was exceeded.
        cap: u32,
    },
}

/// The inclusive range of usable host addresses of an [`Ipv4Net`]
/// (FR-SC-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRange {
    first: Ipv4Addr,
    last: Ipv4Addr,
}

impl HostRange {
    /// The first usable host address.
    pub fn first(&self) -> Ipv4Addr {
        self.first
    }

    /// The last usable host address.
    pub fn last(&self) -> Ipv4Addr {
        self.last
    }
}

impl fmt::Display for HostRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}–{}", self.first, self.last)
    }
}

impl Ipv4Net {
    /// Creates the network containing `addr`, masking off the host bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use osza_netmon::model::ipv4::Ipv4Net;
    ///
    /// let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 130), 24)
    ///     .expect("valid network");
    /// assert_eq!(net.network(), Ipv4Addr::new(192, 168, 1, 0));
    /// ```
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, Ipv4NetError> {
        if prefix_len > 32 {
            return Err(Ipv4NetError::InvalidPrefix { found: prefix_len });
        }
        let mask = mask_bits(prefix_len);
        Ok(Ipv4Net {
            network: Ipv4Addr::from(u32::from(addr) & mask),
            prefix_len,
        })
    }

    /// The network base address (host bits zero).
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// The prefix length (`0..=32`).
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The netmask as an address (e.g. `255.255.255.0` for /24).
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask_bits(self.prefix_len))
    }

    /// The broadcast address (all host bits set); for /31 and /32 this is
    /// the last address of the network (the RFC 3021 view).
    pub fn broadcast(&self) -> Ipv4Addr {
        let mask = mask_bits(self.prefix_len);
        Ipv4Addr::from(u32::from(self.network) | !mask)
    }

    /// `true` if `ip` lies inside the network (network and broadcast
    /// addresses included).
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = mask_bits(self.prefix_len);
        u32::from(ip) & mask == u32::from(self.network)
    }

    /// The number of usable host addresses (FR-SC-05):
    ///
    /// * prefix `0..=30`: `2^(32-prefix) - 2` (network and broadcast are
    ///   not hosts);
    /// * `/31`: 2 (RFC 3021, both addresses are hosts);
    /// * `/32`: 1 (the address itself).
    ///
    /// Computed in `u64` so a `/0` cannot overflow (plan SR-02).
    pub fn host_count(&self) -> u32 {
        match self.prefix_len {
            32 => 1,
            31 => 2,
            prefix => {
                // prefix <= 30 here, so the count is at most 2^32 - 2 and
                // always fits u32.
                let count = (1u64 << (32 - u64::from(prefix))) - 2;
                count as u32
            }
        }
    }

    /// The usable host range under the default cap
    /// ([`DEFAULT_MAX_HOSTS`], 1,022 hosts = /22, FR-SC-06).
    ///
    /// Networks with more usable hosts than the cap return
    /// [`Ipv4NetError::OverCapacity`] — larger scans require an explicit
    /// raised cap via [`host_range_capped`](Self::host_range_capped).
    pub fn host_range(&self) -> Result<HostRange, Ipv4NetError> {
        self.host_range_capped(DEFAULT_MAX_HOSTS)
    }

    /// The usable host range under an explicit cap.
    ///
    /// The cap itself is validated against [`ABSOLUTE_MAX_HOSTS`] first;
    /// then a network whose [`host_count`](Self::host_count) exceeds the
    /// cap is rejected with [`Ipv4NetError::OverCapacity`].
    pub fn host_range_capped(&self, max_hosts: u32) -> Result<HostRange, Ipv4NetError> {
        if max_hosts > ABSOLUTE_MAX_HOSTS {
            return Err(Ipv4NetError::InvalidMaxHosts {
                found: max_hosts,
                max: ABSOLUTE_MAX_HOSTS,
            });
        }
        let requested = self.host_count();
        if requested > max_hosts {
            return Err(Ipv4NetError::OverCapacity {
                requested,
                cap: max_hosts,
            });
        }
        let network = u32::from(self.network);
        let (first, last) = match self.prefix_len {
            32 => (network, network),
            31 => (network, network + 1),
            _ => (network + 1, u32::from(self.broadcast()) - 1),
        };
        Ok(HostRange {
            first: Ipv4Addr::from(first),
            last: Ipv4Addr::from(last),
        })
    }
}

impl TryFrom<(Ipv4Addr, u8)> for Ipv4Net {
    type Error = Ipv4NetError;

    fn try_from((addr, prefix_len): (Ipv4Addr, u8)) -> Result<Self, Self::Error> {
        Ipv4Net::new(addr, prefix_len)
    }
}

/// The netmask of `prefix_len` as raw bits (`0` for /0; the shift below
/// would overflow for it).
fn mask_bits(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;

    fn addr(o: [u8; 4]) -> Ipv4Addr {
        let [a, b, c, d] = o;
        Ipv4Addr::new(a, b, c, d)
    }

    // ---- classification (table-driven, all boundaries) ----------------------

    #[test]
    fn classifies_private_link_local_and_cgnat_ranges() {
        // (address, is_private, is_link_local, is_cgnat)
        let table: [([u8; 4], bool, bool, bool); 30] = [
            // RFC 1918 interiors and exact boundaries.
            ([10, 0, 0, 0], true, false, false),
            ([10, 255, 255, 255], true, false, false),
            ([10, 1, 2, 3], true, false, false),
            ([9, 255, 255, 255], false, false, false),
            ([11, 0, 0, 0], false, false, false),
            ([172, 16, 0, 0], true, false, false),
            ([172, 31, 255, 255], true, false, false),
            ([172, 20, 0, 1], true, false, false),
            ([172, 15, 255, 255], false, false, false),
            ([172, 32, 0, 0], false, false, false),
            ([192, 168, 0, 0], true, false, false),
            ([192, 168, 255, 255], true, false, false),
            ([192, 169, 0, 0], false, false, false),
            ([192, 167, 255, 255], false, false, false),
            // Link-local 169.254.0.0/16.
            ([169, 254, 0, 0], false, true, false),
            ([169, 254, 255, 255], false, true, false),
            ([169, 254, 1, 1], false, true, false),
            ([169, 253, 255, 255], false, false, false),
            ([169, 255, 0, 0], false, false, false),
            // CGNAT 100.64.0.0/10.
            ([100, 64, 0, 0], false, false, true),
            ([100, 127, 255, 255], false, false, true),
            ([100, 100, 1, 2], false, false, true),
            ([100, 63, 255, 255], false, false, false),
            ([100, 128, 0, 0], false, false, false),
            // Public and special addresses: none of the three.
            ([8, 8, 8, 8], false, false, false),
            ([1, 1, 1, 1], false, false, false),
            ([203, 0, 113, 7], false, false, false),
            ([127, 0, 0, 1], false, false, false),
            ([0, 0, 0, 0], false, false, false),
            ([255, 255, 255, 255], false, false, false),
        ];
        for (o, private, link_local, cgnat) in table {
            let ip = addr(o);
            assert_eq!(is_private(ip), private, "is_private({ip})");
            assert_eq!(is_link_local(ip), link_local, "is_link_local({ip})");
            assert_eq!(is_cgnat(ip), cgnat, "is_cgnat({ip})");
        }
    }

    // ---- Ipv4Net construction -----------------------------------------------

    #[test]
    fn rejects_invalid_prefix_lengths() {
        for bad in [33u8, 64, 255] {
            assert_eq!(
                Ipv4Net::new(addr([192, 168, 1, 1]), bad).unwrap_err(),
                Ipv4NetError::InvalidPrefix { found: bad }
            );
        }
        // /0 and /32 are the extreme valid prefixes.
        assert!(Ipv4Net::new(addr([1, 2, 3, 4]), 0).is_ok());
        assert!(Ipv4Net::new(addr([1, 2, 3, 4]), 32).is_ok());
    }

    #[test]
    fn host_bits_are_masked_off_at_construction() {
        let net = Ipv4Net::new(addr([192, 168, 1, 130]), 24).expect("valid");
        assert_eq!(net.network(), addr([192, 168, 1, 0]));
        assert_eq!(net.prefix_len(), 24);
        assert_eq!(net.netmask(), addr([255, 255, 255, 0]));
        assert_eq!(net.broadcast(), addr([192, 168, 1, 255]));
        // Any address inside yields the same network.
        let twin = Ipv4Net::new(addr([192, 168, 1, 7]), 24).expect("valid");
        assert_eq!(net, twin);
        let (a, p) = (addr([10, 0, 0, 0]), 8);
        assert_eq!(Ipv4Net::try_from((a, p)).expect("valid").prefix_len(), 8);
    }

    #[test]
    fn netmask_and_broadcast_cover_the_extreme_prefixes() {
        let cases: [(u8, [u8; 4], [u8; 4]); 6] = [
            (0, [0, 0, 0, 0], [255, 255, 255, 255]),
            (8, [255, 0, 0, 0], [10, 255, 255, 255]),
            (16, [255, 255, 0, 0], [172, 16, 255, 255]),
            (22, [255, 255, 252, 0], [192, 168, 7, 255]),
            (31, [255, 255, 255, 254], [10, 0, 0, 1]),
            (32, [255, 255, 255, 255], [10, 0, 0, 5]),
        ];
        for (prefix, mask, bcast) in cases {
            let net = Ipv4Net::new(addr(bcast), prefix).expect("valid prefix");
            assert_eq!(net.netmask(), addr(mask), "netmask /{prefix}");
            assert_eq!(net.broadcast(), addr(bcast), "broadcast /{prefix}");
        }
    }

    #[test]
    fn contains_covers_the_whole_network_and_nothing_else() {
        let net = Ipv4Net::new(addr([192, 168, 4, 100]), 22).expect("valid");
        // Network 192.168.4.0/22 spans 192.168.4.0 - 192.168.7.255.
        assert!(net.contains(addr([192, 168, 4, 0])));
        assert!(net.contains(addr([192, 168, 5, 128])));
        assert!(net.contains(addr([192, 168, 7, 255])));
        assert!(!net.contains(addr([192, 168, 3, 255])));
        assert!(!net.contains(addr([192, 168, 8, 0])));
        // /32 contains exactly its own address.
        let host = Ipv4Net::new(addr([10, 0, 0, 5]), 32).expect("valid");
        assert!(host.contains(addr([10, 0, 0, 5])));
        assert!(!host.contains(addr([10, 0, 0, 6])));
    }

    // ---- host counts and ranges (card: /24, /22, /30, /31, /32, /16 over-cap)

    #[test]
    fn host_counts_match_the_prefix_rules() {
        let cases: [(u8, u32); 9] = [
            (0, 4_294_967_294),
            (8, 16_777_214),
            (16, 65_534),
            (22, 1022),
            (24, 254),
            (30, 2),
            (31, 2),
            (32, 1),
            (28, 14),
        ];
        for (prefix, expected) in cases {
            let net = Ipv4Net::new(addr([10, 0, 0, 0]), prefix).expect("valid prefix");
            assert_eq!(net.host_count(), expected, "host_count /{prefix}");
        }
    }

    #[test]
    fn host_ranges_for_24_22_30_31_32() {
        let net24 = Ipv4Net::new(addr([192, 168, 1, 0]), 24).expect("valid");
        let range = net24.host_range().expect("254 <= 1022");
        assert_eq!(range.first(), addr([192, 168, 1, 1]));
        assert_eq!(range.last(), addr([192, 168, 1, 254]));
        assert_eq!(range.to_string(), "192.168.1.1–192.168.1.254");

        let net22 = Ipv4Net::new(addr([10, 0, 0, 0]), 22).expect("valid");
        let range = net22.host_range().expect("1022 == default cap, allowed");
        assert_eq!(range.first(), addr([10, 0, 0, 1]));
        assert_eq!(range.last(), addr([10, 0, 3, 254]));

        let net30 = Ipv4Net::new(addr([192, 168, 1, 4]), 30).expect("valid");
        let range = net30.host_range().expect("2 <= 1022");
        assert_eq!(range.first(), addr([192, 168, 1, 5]));
        assert_eq!(range.last(), addr([192, 168, 1, 6]));

        // RFC 3021: both /31 addresses are usable.
        let net31 = Ipv4Net::new(addr([10, 0, 0, 0]), 31).expect("valid");
        let range = net31.host_range().expect("2 <= 1022");
        assert_eq!(range.first(), addr([10, 0, 0, 0]));
        assert_eq!(range.last(), addr([10, 0, 0, 1]));

        let net32 = Ipv4Net::new(addr([10, 0, 0, 5]), 32).expect("valid");
        let range = net32.host_range().expect("1 <= 1022");
        assert_eq!(range.first(), addr([10, 0, 0, 5]));
        assert_eq!(range.last(), addr([10, 0, 0, 5]));
    }

    #[test]
    fn over_capacity_networks_are_detected() {
        // /16 with 65,534 hosts: above the default cap of 1,022 (FR-SC-06).
        let net16 = Ipv4Net::new(addr([172, 16, 0, 0]), 16).expect("valid");
        assert_eq!(
            net16.host_range().unwrap_err(),
            Ipv4NetError::OverCapacity {
                requested: 65_534,
                cap: DEFAULT_MAX_HOSTS
            }
        );
        // /21 (2,046 hosts) is also above the default cap.
        let net21 = Ipv4Net::new(addr([10, 0, 0, 0]), 21).expect("valid");
        assert_eq!(
            net21.host_range().unwrap_err(),
            Ipv4NetError::OverCapacity {
                requested: 2046,
                cap: DEFAULT_MAX_HOSTS
            }
        );
        // With the cap raised to the absolute ceiling, /16 is allowed.
        let range = net16
            .host_range_capped(ABSOLUTE_MAX_HOSTS)
            .expect("65,534 == ceiling");
        assert_eq!(range.first(), addr([172, 16, 0, 1]));
        assert_eq!(range.last(), addr([172, 16, 255, 254]));
        // But the ceiling itself is validated.
        assert_eq!(
            net16.host_range_capped(ABSOLUTE_MAX_HOSTS + 1).unwrap_err(),
            Ipv4NetError::InvalidMaxHosts {
                found: 65_535,
                max: ABSOLUTE_MAX_HOSTS
            }
        );
        // And /15 (131,070 hosts) can never be scanned actively.
        let net15 = Ipv4Net::new(addr([10, 0, 0, 0]), 15).expect("valid");
        assert_eq!(
            net15.host_range_capped(ABSOLUTE_MAX_HOSTS).unwrap_err(),
            Ipv4NetError::OverCapacity {
                requested: 131_070,
                cap: ABSOLUTE_MAX_HOSTS
            }
        );
    }

    // ---- property-style tests -------------------------------------------------

    /// Property (exhaustive over all 33 prefix lengths): host counts follow
    /// the prefix rules and the default/absolute caps behave per FR-SC-06.
    #[test]
    fn property_host_math_holds_for_every_prefix_length() {
        for prefix in 0u8..=32 {
            let net = Ipv4Net::new(addr([203, 0, 113, 9]), prefix).expect("0..=32 all valid");
            // Host bits were masked off.
            let mask = mask_bits(prefix);
            assert_eq!(u32::from(net.network()) & mask, u32::from(net.network()));
            // Count matches the formula.
            let expected = match prefix {
                32 => 1,
                31 => 2,
                p => ((1u64 << (32 - u64::from(p))) - 2) as u32,
            };
            assert_eq!(net.host_count(), expected, "count /{prefix}");
            // The absolute ceiling admits exactly the /32../16 family.
            let capped = net.host_range_capped(ABSOLUTE_MAX_HOSTS);
            if prefix >= 16 {
                let range = capped.expect("<= 65,534 hosts");
                assert!(u32::from(range.first()) <= u32::from(range.last()));
            } else {
                assert_eq!(
                    capped.unwrap_err(),
                    Ipv4NetError::OverCapacity {
                        requested: expected,
                        cap: ABSOLUTE_MAX_HOSTS
                    }
                );
            }
            // The default cap admits exactly the /22..../32 family.
            let default_capped = net.host_range();
            if expected <= DEFAULT_MAX_HOSTS {
                default_capped.expect("within default cap");
            } else {
                assert_eq!(
                    default_capped.unwrap_err(),
                    Ipv4NetError::OverCapacity {
                        requested: expected,
                        cap: DEFAULT_MAX_HOSTS
                    }
                );
            }
        }
    }

    /// Property: for random address/prefix pairs, every generated member
    /// address is `contains`-inside its network, and the network base is
    /// the masked address.
    #[test]
    fn property_contains_every_generated_member() {
        let mut rng = Lcg::seeded(0x1E7_0005);
        for _ in 0..500 {
            let raw = rng.next_u64() as u32;
            let ip = Ipv4Addr::from(raw);
            let prefix = rng.next_below(33) as u8;
            let net = Ipv4Net::new(ip, prefix).expect("valid by construction");
            assert!(net.contains(ip), "{ip} must be inside {net:?}");
            assert!(net.contains(net.network()));
            assert!(net.contains(net.broadcast()));
            let base = raw & mask_bits(prefix);
            assert_eq!(net.network(), Ipv4Addr::from(base));
        }
    }
}
