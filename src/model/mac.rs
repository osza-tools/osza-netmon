// SPDX-License-Identifier: GPL-3.0-only

//! Validated MAC address type ([`MacAddr`]) — plan §5.2–5.3, task T-002.
//!
//! `MacAddr` is the boundary type for Ethernet sender addresses. Per plan
//! §5.3 ("Invalid MAC"), the all-zero, broadcast and multicast (multicast
//! bit set) sender MACs are rejected at the boundary: every constructor —
//! string parsing and raw octets — refuses them, so a `MacAddr` value is
//! always a valid *sender/device* MAC. Locally-administered addresses are
//! accepted; the UI labels them `Private address` (plan §5.3, FR-EN-01).
//!
//! Parsing accepts the three notations used by `/proc/net/arp` and friends,
//! case-insensitively: `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` and
//! `aabbccddeeff`. Parsing is total (plan SR-02): any input is either
//! accepted or mapped to a [`MacAddrParseError`]; nothing panics, and no
//! input is trimmed or repaired silently.

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

/// A validated unicast MAC address (plan §5.2).
///
/// The type is constructible only through validation ([`FromStr`],
/// [`TryFrom<&str>`](TryFrom) or [`MacAddr::from_octets`]); the octets are
/// private. The canonical [`fmt::Display`] form is lowercase colon-separated
/// (`aa:bb:cc:dd:ee:ff`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr {
    octets: [u8; 6],
}

/// Errors returned when text or raw octets are rejected by [`MacAddr`].
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MacAddrParseError {
    /// The input was empty.
    #[error("MAC address is empty")]
    Empty,
    /// The input length matches neither 12 hex digits nor 17 characters
    /// with separators.
    #[error(
        "MAC address has invalid length: expected 12 hex digits or 17 characters with separators, found {found} characters"
    )]
    InvalidLength {
        /// Number of characters in the rejected input.
        found: usize,
    },
    /// A character that is neither a hex digit nor an accepted separator
    /// appeared at `position`.
    #[error("MAC address contains invalid character {found:?} at position {position}")]
    InvalidCharacter {
        /// The offending character.
        found: char,
        /// Zero-based character position of `found`.
        position: usize,
    },
    /// Both `:` and `-` were used as separators, or the separators are not
    /// the same character throughout.
    #[error("MAC address mixes ':' and '-' separators")]
    InvalidSeparators,
    /// The address is the all-zero address, rejected at the boundary
    /// (plan §5.3).
    #[error("MAC address is all-zero; rejected at the boundary")]
    ZeroAddress,
    /// The address is the broadcast address, rejected at the boundary
    /// (plan §5.3).
    #[error("MAC address is broadcast; rejected at the boundary")]
    BroadcastAddress,
    /// The multicast bit (first octet, bit 0) is set, rejected at the
    /// boundary (plan §5.3).
    #[error("MAC address has the multicast bit set; rejected at the boundary")]
    MulticastAddress,
}

impl MacAddr {
    /// Builds a `MacAddr` from raw octets, enforcing the same boundary
    /// rules as string parsing (plan §5.3): all-zero, broadcast and
    /// multicast addresses are rejected.
    ///
    /// Packet and neighbor-table readers (T-102/T-103) call this with
    /// externally sourced octets, so this is a validating constructor, not a
    /// trusted one.
    pub fn from_octets(octets: [u8; 6]) -> Result<Self, MacAddrParseError> {
        if octets == [0; 6] {
            return Err(MacAddrParseError::ZeroAddress);
        }
        if octets == [0xff; 6] {
            return Err(MacAddrParseError::BroadcastAddress);
        }
        let [first, ..] = octets;
        if first & 0x01 != 0 {
            return Err(MacAddrParseError::MulticastAddress);
        }
        Ok(Self { octets })
    }

    /// The six address octets.
    pub const fn octets(&self) -> [u8; 6] {
        self.octets
    }

    /// `true` if the multicast bit (first octet, bit 0) is set.
    ///
    /// A successfully constructed `MacAddr` is always unicast, so this
    /// returns `false` for every value that exists; the predicate is the
    /// classifier the constructors use to reject raw addresses, and it is
    /// public so boundary code and tests can classify arbitrary octets
    /// (plan Appendix E: "first octet bit 0 = multicast").
    pub const fn is_multicast(&self) -> bool {
        let [first, ..] = self.octets;
        first & 0x01 != 0
    }

    /// `true` if the locally-administered bit (first octet, bit 1) is set.
    ///
    /// Such MACs are valid senders (phones using Wi-Fi privacy features,
    /// virtual machines, containers); the UI shows the label
    /// `Private address` for them (plan §5.3, FR-EN-01).
    pub const fn is_locally_administered(&self) -> bool {
        let [first, ..] = self.octets;
        first & 0x02 != 0
    }

    /// `true` for the all-zero address. See [`is_multicast`](Self::is_multicast)
    /// for why this is `false` for every value that exists.
    pub fn is_zero(&self) -> bool {
        self.octets == [0; 6]
    }

    /// `true` for the broadcast address. See [`is_multicast`](Self::is_multicast)
    /// for why this is `false` for every value that exists.
    pub fn is_broadcast(&self) -> bool {
        self.octets == [0xff; 6]
    }
}

impl FromStr for MacAddr {
    type Err = MacAddrParseError;

    /// Parses one of the three accepted notations, case-insensitively:
    /// `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabbccddeeff`.
    ///
    /// The input is used exactly as given: no trimming, no case folding of
    /// separators, no silent repair (plan SR-04). Positions in errors are
    /// zero-based character positions.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let count = s.chars().count();
        if count == 0 {
            return Err(MacAddrParseError::Empty);
        }
        // 12 characters can only be the bare form; 17 can only be the
        // separated form; anything else matches neither.
        if count != 12 && count != 17 {
            return Err(MacAddrParseError::InvalidLength { found: count });
        }
        let separated = count == 17;

        let mut separator: Option<char> = None;
        let mut hex_digits: usize = 0;
        let mut packed: u64 = 0;

        for (position, c) in s.chars().enumerate() {
            let separator_slot = separated && matches!(position, 2 | 5 | 8 | 11 | 14);
            if separator_slot {
                if c != ':' && c != '-' {
                    return Err(MacAddrParseError::InvalidCharacter { found: c, position });
                }
                match separator {
                    None => separator = Some(c),
                    Some(seen) if seen == c => {}
                    Some(_) => return Err(MacAddrParseError::InvalidSeparators),
                }
            } else if let Some(digit) = hex_digit(c) {
                packed = (packed << 4) | u64::from(digit);
                hex_digits += 1;
            } else {
                return Err(MacAddrParseError::InvalidCharacter { found: c, position });
            }
        }

        // Defensive totality check: the length rules above already pin the
        // structure, so a mismatch here is a logic error, reported as an
        // error instead of a panic (plan SR-02).
        if hex_digits != 12 {
            return Err(MacAddrParseError::InvalidLength { found: count });
        }

        let octets = [
            packed_octet(packed, 0),
            packed_octet(packed, 1),
            packed_octet(packed, 2),
            packed_octet(packed, 3),
            packed_octet(packed, 4),
            packed_octet(packed, 5),
        ];
        MacAddr::from_octets(octets)
    }
}

impl TryFrom<&str> for MacAddr {
    type Error = MacAddrParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<[u8; 6]> for MacAddr {
    type Error = MacAddrParseError;

    fn try_from(octets: [u8; 6]) -> Result<Self, Self::Error> {
        MacAddr::from_octets(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.octets;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Hex digit value of `c`, or `None` for any non-hex character.
fn hex_digit(c: char) -> Option<u32> {
    c.to_digit(16)
}

/// Byte `index` (0–5) of the 48 bits packed into the low bits of `packed`.
fn packed_octet(packed: u64, index: u32) -> u8 {
    ((packed >> (40 - 8 * index)) & 0xff) as u8
}

#[allow(dead_code)]
fn violation_println() {
    println!("violation");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // ---- accepted formats -------------------------------------------------

    #[test]
    fn parses_colon_dash_and_bare_notations() {
        for text in [
            "aa:bb:cc:dd:ee:ff",
            "aa-bb-cc-dd-ee-ff",
            "aabbccddeeff",
            "AA:BB:CC:DD:EE:FF",
            "Aa-Bb-cC-dD-eE-fF",
            "AABBCCDDEEFF",
        ] {
            let parsed = MacAddr::from_str(text);
            assert_eq!(
                parsed,
                Ok(MacAddr {
                    octets: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
                }),
                "expected {text:?} to parse"
            );
        }
    }

    #[test]
    fn display_is_canonical_lowercase_colon_form() {
        let mac = MacAddr {
            octets: [0x0a, 0xbc, 0xde, 0xf0, 0x12, 0x34],
        };
        assert_eq!(mac.to_string(), "0a:bc:de:f0:12:34");
        // Round trip: parsing the display form yields the same value.
        assert_eq!(mac.to_string().parse::<MacAddr>(), Ok(mac));
    }

    #[test]
    fn try_from_str_and_from_octets_agree() {
        let via_str: MacAddr = "02-00-00-00-00-01".try_into().expect("valid sender MAC");
        let via_octets = MacAddr::try_from([0x02, 0, 0, 0, 0, 0x01]).expect("valid sender MAC");
        assert_eq!(via_str, via_octets);
        assert_eq!(via_octets.octets(), [0x02, 0, 0, 0, 0, 0x01]);
    }

    // ---- predicates --------------------------------------------------------

    #[test]
    fn predicates_classify_boundary_relevant_octets() {
        // is_locally_administered: bit 1 of the first octet.
        assert!(
            MacAddr {
                octets: [0x02, 1, 2, 3, 4, 5]
            }
            .is_locally_administered()
        );
        assert!(
            MacAddr {
                octets: [0xaa, 1, 2, 3, 4, 5]
            }
            .is_locally_administered()
        );
        assert!(
            !MacAddr {
                octets: [0x00, 1, 2, 3, 4, 5]
            }
            .is_locally_administered()
        );

        // The raw classifiers, exercised with values that the constructors
        // reject (reachable in this module's tests through the private
        // fields): multicast bit, all-zero, broadcast.
        assert!(
            MacAddr {
                octets: [0x01, 0, 0, 0, 0, 1]
            }
            .is_multicast()
        );
        assert!(MacAddr { octets: [0xff; 6] }.is_multicast());
        assert!(MacAddr { octets: [0x00; 6] }.is_zero());
        assert!(MacAddr { octets: [0xff; 6] }.is_broadcast());

        // And for every constructible value the rejected classes are false.
        let mac = MacAddr::from_octets([0x00, 1, 2, 3, 4, 5]).expect("unicast non-zero");
        assert!(!mac.is_multicast());
        assert!(!mac.is_zero());
        assert!(!mac.is_broadcast());
    }

    #[test]
    fn boundary_rejections_are_descriptive() {
        assert_eq!(
            "00:00:00:00:00:00".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::ZeroAddress
        );
        assert_eq!(
            "000000000000".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::ZeroAddress
        );
        assert_eq!(
            "ff:ff:ff:ff:ff:ff".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::BroadcastAddress
        );
        // IPv4 multicast MAC (01:00:5e:...) and IPv6 multicast MAC
        // (33:33:...): multicast bit set.
        assert_eq!(
            "01:00:5e:00:00:01".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::MulticastAddress
        );
        assert_eq!(
            "33:33:00:00:00:01".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::MulticastAddress
        );
        assert_eq!(
            "01005e000001".parse::<MacAddr>().unwrap_err(),
            MacAddrParseError::MulticastAddress
        );
        assert_eq!(
            MacAddr::from_octets([0x03, 1, 2, 3, 4, 5]).unwrap_err(),
            MacAddrParseError::MulticastAddress
        );
    }

    // ---- rejection of malformed input --------------------------------------

    #[test]
    fn rejects_malformed_strings_with_positions() {
        let cases: [(&str, MacAddrParseError); 13] = [
            ("", MacAddrParseError::Empty),
            (
                "aa:bb:cc:dd:ee",
                MacAddrParseError::InvalidLength { found: 14 },
            ),
            (
                "aabbccddeef",
                MacAddrParseError::InvalidLength { found: 11 },
            ),
            (
                "aabbccddeeffa",
                MacAddrParseError::InvalidLength { found: 13 },
            ),
            (
                "aa:bb:cc:dd:ee:ff:",
                MacAddrParseError::InvalidLength { found: 18 },
            ),
            (
                " aa:bb:cc:dd:ee:ff",
                MacAddrParseError::InvalidLength { found: 18 },
            ),
            (
                "aa:bb:cc:dd:ee:ff\n",
                MacAddrParseError::InvalidLength { found: 18 },
            ),
            ("aa:bb-cc:dd:ee:ff", MacAddrParseError::InvalidSeparators),
            (
                "aa.bb.cc.dd.ee.ff",
                MacAddrParseError::InvalidCharacter {
                    found: '.',
                    position: 2,
                },
            ),
            (
                "aabbccddeefg",
                MacAddrParseError::InvalidCharacter {
                    found: 'g',
                    position: 11,
                },
            ),
            (
                "gabbccddeeff",
                MacAddrParseError::InvalidCharacter {
                    found: 'g',
                    position: 0,
                },
            ),
            (
                "aa:bb:cc:dd:ee:fg",
                MacAddrParseError::InvalidCharacter {
                    found: 'g',
                    position: 16,
                },
            ),
            // Fullwidth digits are not ASCII hex digits (12 chars, so the
            // length gate passes and the character gate fires).
            (
                "\u{ff41}abbccddeeff",
                MacAddrParseError::InvalidCharacter {
                    found: '\u{ff41}',
                    position: 0,
                },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                input.parse::<MacAddr>().unwrap_err(),
                expected,
                "input: {input:?}"
            );
        }
    }

    // ---- ordering and hashing ----------------------------------------------

    #[test]
    fn ordering_is_octet_lexicographic_and_hash_matches_eq() {
        let small = MacAddr {
            octets: [0, 0, 0, 0, 0, 1],
        };
        let large = MacAddr {
            octets: [0, 0, 0, 0, 0, 2],
        };
        let same_as_small = small;
        assert!(small < large);
        assert_eq!(small, same_as_small);

        let hash = |m: &MacAddr| {
            let mut hasher = DefaultHasher::new();
            m.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash(&small), hash(&same_as_small));

        let mut map = std::collections::HashMap::new();
        map.insert(small, 1u8);
        assert_eq!(map.get(&same_as_small), Some(&1));
    }

    // ---- property-style tests (deterministic, std-only) --------------------

    /// Property: for every valid unicast non-zero MAC, parsing the canonical
    /// display form returns the original value (parse ∘ format = identity).
    #[test]
    fn property_round_trip_all_valid_macs() {
        let mut rng = Lcg::seeded(0x00C0_FFEE_0001);
        for _ in 0..256 {
            // Force the multicast bit clear so the address is a valid sender.
            let mut octets = [0u8; 6];
            for slot in octets.iter_mut() {
                *slot = rng.next_u8();
            }
            let [first, ..] = octets;
            octets[0] = first & 0xfe;
            if octets == [0; 6] {
                octets[5] = 1; // keep all-zero out of the valid population
            }
            let mac = MacAddr::from_octets(octets).expect("unicast, non-zero, non-broadcast");
            let formatted = mac.to_string();
            let reparsed = formatted
                .parse::<MacAddr>()
                .expect("canonical form always parses");
            assert_eq!(reparsed, mac, "round trip failed for {formatted}");
            assert_eq!(reparsed.octets(), octets);
        }
    }

    /// Property: parsing arbitrary hostile strings never panics; every input
    /// maps to Ok or a descriptive error, and Ok values round-trip. In
    /// parallel, every 12-hex-digit string must pass the *format* stage:
    /// rejection can only be a plan §5.3 boundary rule (zero, broadcast,
    /// multicast), never a format error.
    #[test]
    fn property_parse_never_panics_on_hostile_input() {
        const ALPHABET: [char; 24] = [
            '0', '1', '9', 'a', 'f', 'A', 'F', 'g', 'z', ':', '-', '.', ' ', '\t', '\n', '\u{0}',
            '\u{1b}', '\u{7f}', '\u{ff41}', '\u{202e}', '\u{feff}', '/', '#', '\u{2028}',
        ];
        let mut rng = Lcg::seeded(0xBA0D_0002);
        for _ in 0..1000 {
            let len = rng.next_below(40) as usize;
            let mut text = String::new();
            for _ in 0..len {
                let index = rng.next_below(ALPHABET.len() as u64) as usize;
                text.push(ALPHABET[index]);
            }
            // Total parser: Ok or Err, never a panic (SR-02). Ok values
            // (rare with this alphabet) must round-trip.
            if let Ok(mac) = MacAddr::from_str(&text) {
                assert_eq!(mac.to_string().parse::<MacAddr>(), Ok(mac));
            }
        }

        // Any 12-hex-digit string is format-valid: it either constructs a
        // unicast sender MAC or is rejected solely by a §5.3 boundary rule.
        const HEX: [char; 16] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let mut formatted_ok = 0;
        for _ in 0..300 {
            let mut text = String::new();
            for _ in 0..12 {
                let index = rng.next_below(HEX.len() as u64) as usize;
                text.push(HEX[index]);
            }
            match MacAddr::from_str(&text) {
                Ok(mac) => {
                    formatted_ok += 1;
                    assert_eq!(mac.to_string().parse::<MacAddr>(), Ok(mac));
                    assert_eq!(mac.to_string().to_ascii_lowercase(), mac.to_string());
                }
                Err(e) => assert!(
                    matches!(
                        e,
                        MacAddrParseError::ZeroAddress
                            | MacAddrParseError::BroadcastAddress
                            | MacAddrParseError::MulticastAddress
                    ),
                    "format-valid input {text:?} must only fail a §5.3 rule, got {e:?}"
                ),
            }
        }
        // Unicast non-zero addresses are common in 300 tries; the guard
        // keeps the property from becoming silently vacuous if the
        // generator is ever broken.
        assert!(
            formatted_ok > 0,
            "generator never produced a valid MAC; property is vacuous"
        );
    }
}
