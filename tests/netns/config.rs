// SPDX-License-Identifier: GPL-3.0-only

//! The responder configuration file (task T-106).
//!
//! The test process writes one `responder.conf` per lab; the re-exec'd
//! responder (option (a) of the task card §3: self-reexec, no new
//! artifact) parses it. The format is line-based `key value…` text — the
//! same philosophy as the `/proc` parsers of T-102: no new dependency
//! (AGENTS.md rule 3), total parsing, bounded size, fail-closed on
//! unknown keys.
//!
//! Every value that shapes behavior is in here, including the impairment
//! seed, so a measurement artifact plus its config reproduces a run.

use std::fmt;
use std::net::Ipv4Addr;

use osza_netmon::model::MacAddr;

/// Bounded read: a config larger than this is refused (hostile-input
/// rules, AGENTS.md rule 4 — the file is ours, but bounds stay).
pub const CONFIG_MAX_BYTES: u64 = 256 * 1024;

/// One answered address: the reply claims `mac` for `ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The address the responder answers for.
    pub ip: Ipv4Addr,
    /// The synthetic MAC it claims (locally administered, `02:…`).
    pub mac: MacAddr,
}

/// The hostile mode the responder injects once, when it sees the first
/// ARP request (plan §11.2 S5; task card §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hostile {
    /// No hostile traffic (the default).
    None,
    /// A *valid* reply for `ip` before the scanner solicits it —
    /// rejected as `NotSolicited` if it wins the race (deterministic:
    /// `ip` must sort after the first target; the responder logs a guard
    /// violation if it does not).
    Unsolicited {
        /// The in-scope address claimed by the un-asked reply.
        ip: Ipv4Addr,
    },
    /// A 20-byte cut-down reply — `Truncated`.
    Truncated {
        /// The address the cut frame would claim.
        ip: Ipv4Addr,
    },
    /// A structurally valid reply whose sender MAC is multicast —
    /// `InvalidMac`.
    MulticastMac {
        /// The address the reply claims.
        ip: Ipv4Addr,
    },
    /// A structurally valid reply whose sender IP is outside the scan
    /// scope — `OutOfScope`.
    OutOfScope {
        /// The out-of-scope address claimed (the test picks one from a
        /// different RFC 5737 range than the lab's own).
        ip: Ipv4Addr,
    },
    /// `count` valid replies spread round-robin over the answer table as
    /// fast as the responder can send — the flood must not hang the scan
    /// or exceed the response cap (plan §11.2 S5).
    Flood {
        /// Total hostile reply frames to send.
        count: u32,
    },
}

/// The impairment a helper-answered address suffers (Appendix D P0–P3 +
/// the S9 sleepy parameters; helper-based impairment is the default and
/// the CI mechanism — task card §3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Impairment {
    /// RNG seed — recorded in the log and the measurement artifacts.
    pub seed: u64,
    /// Per-address probability of silently dropping a request
    /// (P1: 0.05, P2: 0.20).
    pub drop_prob: f64,
    /// Delay lower bound in ms, drawn uniformly per answered request
    /// (P2: 50; S9-late: 300). `delay_max == 0` means no delay.
    pub delay_min_ms: u64,
    /// Delay upper bound in ms (P2: 200; S9-late: 500 — "fixed delay +
    /// seeded jitter" as a uniform range).
    pub delay_max_ms: u64,
    /// How many of the first requests per address are ignored outright
    /// (P3: 1; S9-ignore: 2). The counter lives as long as the
    /// responder, so it spans scan cycles.
    pub ignore_first: u32,
    /// Fraction of the remaining requests actually answered
    /// (P3: 0.75, S9-fraction: 0.5).
    pub answer_fraction: f64,
}

impl Impairment {
    /// P0 — no impairment (the seed still flows for logging symmetry).
    pub fn none(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            ignore_first: 0,
            answer_fraction: 1.0,
        }
    }

    /// P1 — 5% frame loss (Appendix D).
    pub fn p1(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.05,
            delay_min_ms: 0,
            delay_max_ms: 0,
            ignore_first: 0,
            answer_fraction: 1.0,
        }
    }

    /// P2 — 20% loss plus 50–200 ms delay/jitter (Appendix D).
    pub fn p2(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.20,
            delay_min_ms: 50,
            delay_max_ms: 200,
            ignore_first: 0,
            answer_fraction: 1.0,
        }
    }

    /// P3 — sleepy hosts: ignore the first request, answer 75%, reply
    /// 150–250 ms late (Appendix D "sleepy hosts"; the S9 variants
    /// stress one knob each).
    pub fn p3(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 150,
            delay_max_ms: 250,
            ignore_first: 1,
            answer_fraction: 0.75,
        }
    }

    /// S9 variant (a): ignore the first two requests, then answer
    /// everything (power-save client that sleeps through a whole scan).
    pub fn s9_ignore_first(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            ignore_first: 2,
            answer_fraction: 1.0,
        }
    }

    /// S9 variant (b): answer only half the requests.
    pub fn s9_fraction(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            ignore_first: 0,
            answer_fraction: 0.5,
        }
    }

    /// S9 variant (c): answer late, 300–500 ms (fixed 400 ms delay with
    /// ±100 ms seeded jitter, expressed as a range).
    pub fn s9_late(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 300,
            delay_max_ms: 500,
            ignore_first: 0,
            answer_fraction: 1.0,
        }
    }
}

impl fmt::Display for Impairment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seed={} drop={:.3} delay={}..{}ms ignore_first={} fraction={:.3}",
            self.seed,
            self.drop_prob,
            self.delay_min_ms,
            self.delay_max_ms,
            self.ignore_first,
            self.answer_fraction
        )
    }
}

/// The parsed responder configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponderConfig {
    /// The interface the responder binds to (the device-side veth end).
    pub iface: String,
    /// The impairment parameters (seeded, recorded).
    pub impairment: Impairment,
    /// The hostile mode (fires once, on the first request).
    pub hostile: Hostile,
    /// The answer table (`ip → mac`), possibly empty (silent helper
    /// that only logs — S2/S3).
    pub answers: Vec<Answer>,
}

impl ResponderConfig {
    /// Serializes the config into the line-based format.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(256 + 32 * self.answers.len());
        out.push_str("# osza-netmon netns responder config v1\n");
        out.push_str(&format!("iface {}\n", self.iface));
        let imp = &self.impairment;
        out.push_str(&format!("seed {}\n", imp.seed));
        out.push_str(&format!("drop {:.3}\n", imp.drop_prob));
        out.push_str(&format!("delay_min_ms {}\n", imp.delay_min_ms));
        out.push_str(&format!("delay_max_ms {}\n", imp.delay_max_ms));
        out.push_str(&format!("ignore_first {}\n", imp.ignore_first));
        out.push_str(&format!("answer_fraction {:.3}\n", imp.answer_fraction));
        match self.hostile {
            Hostile::None => out.push_str("hostile none\n"),
            Hostile::Unsolicited { ip } => {
                out.push_str(&format!("hostile unsolicited\nhostile_ip {ip}\n"));
            }
            Hostile::Truncated { ip } => {
                out.push_str(&format!("hostile truncated\nhostile_ip {ip}\n"));
            }
            Hostile::MulticastMac { ip } => {
                out.push_str(&format!("hostile multicast_mac\nhostile_ip {ip}\n"));
            }
            Hostile::OutOfScope { ip } => {
                out.push_str(&format!("hostile out_of_scope\nhostile_ip {ip}\n"));
            }
            Hostile::Flood { count } => {
                out.push_str(&format!("hostile flood\nflood_count {count}\n"));
            }
        }
        for answer in &self.answers {
            out.push_str(&format!("answer {} {}\n", answer.ip, answer.mac));
        }
        out
    }

    /// Parses the config (total; `Err` carries a one-line reason).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut iface: Option<String> = None;
        let mut seed = 0u64;
        let mut drop_prob = 0.0f64;
        let mut delay_min_ms = 0u64;
        let mut delay_max_ms = 0u64;
        let mut ignore_first = 0u32;
        let mut answer_fraction = 1.0f64;
        let mut hostile = Hostile::None;
        let mut hostile_ip: Option<Ipv4Addr> = None;
        let mut flood_count = 0u32;
        let mut answers = Vec::new();

        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let key = fields.next().unwrap_or_default();
            let fail = |message: &str| format!("line {}: {message}", number + 1);
            match key {
                "iface" => {
                    iface = Some(
                        fields
                            .next()
                            .ok_or_else(|| fail("iface needs a value"))?
                            .to_owned(),
                    );
                }
                "seed" => {
                    seed = fields
                        .next()
                        .ok_or_else(|| fail("seed needs a value"))?
                        .parse()
                        .map_err(|_| fail("seed must be an integer"))?;
                }
                "drop" => {
                    drop_prob = parse_fraction(fields.next(), &fail, "drop")?;
                }
                "delay_min_ms" => {
                    delay_min_ms = parse_u64(fields.next(), &fail, "delay_min_ms")?;
                }
                "delay_max_ms" => {
                    delay_max_ms = parse_u64(fields.next(), &fail, "delay_max_ms")?;
                }
                "ignore_first" => {
                    ignore_first = parse_u64(fields.next(), &fail, "ignore_first")? as u32;
                }
                "answer_fraction" => {
                    answer_fraction = parse_fraction(fields.next(), &fail, "answer_fraction")?;
                }
                "hostile" => {
                    hostile = match fields.next() {
                        Some("none") => Hostile::None,
                        Some("unsolicited") => Hostile::Unsolicited {
                            ip: Ipv4Addr::UNSPECIFIED,
                        },
                        Some("truncated") => Hostile::Truncated {
                            ip: Ipv4Addr::UNSPECIFIED,
                        },
                        Some("multicast_mac") => Hostile::MulticastMac {
                            ip: Ipv4Addr::UNSPECIFIED,
                        },
                        Some("out_of_scope") => Hostile::OutOfScope {
                            ip: Ipv4Addr::UNSPECIFIED,
                        },
                        Some("flood") => Hostile::Flood { count: 0 },
                        _ => {
                            return Err(fail(
                                "hostile must be none|unsolicited|truncated|multicast_mac|out_of_scope|flood",
                            ));
                        }
                    };
                }
                "hostile_ip" => {
                    hostile_ip = Some(
                        fields
                            .next()
                            .ok_or_else(|| fail("hostile_ip needs a value"))?
                            .parse()
                            .map_err(|_| fail("hostile_ip must be an IPv4 address"))?,
                    );
                }
                "flood_count" => {
                    flood_count = parse_u64(fields.next(), &fail, "flood_count")? as u32;
                }
                "answer" => {
                    let ip = fields
                        .next()
                        .ok_or_else(|| fail("answer needs an IP"))?
                        .parse()
                        .map_err(|_| fail("answer IP must parse"))?;
                    let mac = fields
                        .next()
                        .ok_or_else(|| fail("answer needs a MAC"))?
                        .parse()
                        .map_err(|_| fail("answer MAC must parse"))?;
                    answers.push(Answer { ip, mac });
                }
                other => return Err(fail(&format!("unknown key {other:?}"))),
            }
        }

        // Fill the hostile payloads and validate.
        let hostile = match hostile {
            Hostile::None => Hostile::None,
            Hostile::Unsolicited { .. } => Hostile::Unsolicited {
                ip: hostile_ip.ok_or_else(|| "hostile unsolicited needs hostile_ip".to_owned())?,
            },
            Hostile::Truncated { .. } => Hostile::Truncated {
                ip: hostile_ip.ok_or_else(|| "hostile truncated needs hostile_ip".to_owned())?,
            },
            Hostile::MulticastMac { .. } => Hostile::MulticastMac {
                ip: hostile_ip
                    .ok_or_else(|| "hostile multicast_mac needs hostile_ip".to_owned())?,
            },
            Hostile::OutOfScope { .. } => Hostile::OutOfScope {
                ip: hostile_ip.ok_or_else(|| "hostile out_of_scope needs hostile_ip".to_owned())?,
            },
            Hostile::Flood { .. } => Hostile::Flood {
                count: if flood_count == 0 {
                    return Err("hostile flood needs flood_count > 0".to_owned());
                } else {
                    flood_count
                },
            },
        };

        let iface = iface.ok_or_else(|| "iface is required".to_owned())?;
        if delay_max_ms < delay_min_ms {
            return Err("delay_max_ms must be >= delay_min_ms".to_owned());
        }

        Ok(Self {
            iface,
            impairment: Impairment {
                seed,
                drop_prob,
                delay_min_ms,
                delay_max_ms,
                ignore_first,
                answer_fraction,
            },
            hostile,
            answers,
        })
    }
}

/// Parses a bounded `[0, 1]` fraction.
fn parse_fraction(
    raw: Option<&str>,
    fail: &dyn Fn(&str) -> String,
    key: &str,
) -> Result<f64, String> {
    let value: f64 = raw
        .ok_or_else(|| fail(&format!("{key} needs a value")))?
        .parse()
        .map_err(|_| fail(&format!("{key} must be a number")))?;
    if !(0.0..=1.0).contains(&value) {
        return Err(fail(&format!("{key} must be within [0, 1]")));
    }
    Ok(value)
}

/// Parses a non-negative integer.
fn parse_u64(raw: Option<&str>, fail: &dyn Fn(&str) -> String, key: &str) -> Result<u64, String> {
    raw.ok_or_else(|| fail(&format!("{key} needs a value")))?
        .parse()
        .map_err(|_| fail(&format!("{key} must be a non-negative integer")))
}

/// Self-tests of this module (the harness target has no libtest runner;
/// these run as part of the suite's self-check scenario).
pub mod selftests {
    use super::*;

    pub fn config_round_trips() {
        let config = ResponderConfig {
            iface: "v-tstb".to_owned(),
            impairment: Impairment::p2(0xABCD),
            hostile: Hostile::OutOfScope {
                ip: "198.51.100.99".parse().unwrap(),
            },
            answers: vec![Answer {
                ip: "203.0.113.18".parse().unwrap(),
                mac: "02:00:00:00:00:99".parse().unwrap(),
            }],
        };
        let text = config.to_text();
        let parsed =
            ResponderConfig::parse(&text).unwrap_or_else(|err| panic!("round trip failed: {err}"));
        assert_eq!(parsed, config);
    }

    pub fn parse_is_total_and_fail_closed() {
        // Unknown key → error.
        assert!(ResponderConfig::parse("iface x\nbogus 1\n").is_err());
        // Missing iface → error.
        assert!(ResponderConfig::parse("seed 1\n").is_err());
        // Out-of-range fraction → error.
        assert!(ResponderConfig::parse("iface x\nanswer_fraction 1.5\n").is_err());
        // Inverted delay range → error.
        assert!(ResponderConfig::parse("iface x\ndelay_min_ms 200\ndelay_max_ms 50\n").is_err());
        // Garbage never panics.
        assert!(ResponderConfig::parse("\u{1}\u{2} not a config").is_err());
        // Comments and blanks are skipped.
        let parsed = ResponderConfig::parse("# c\n\niface v\n").unwrap();
        assert_eq!(parsed.iface, "v");
        assert_eq!(parsed.answers.len(), 0);
    }

    pub fn profile_parameters_match_appendix_d() {
        let seed = 7;
        let p0 = Impairment::none(seed);
        let p1 = Impairment::p1(seed);
        let p2 = Impairment::p2(seed);
        let p3 = Impairment::p3(seed);
        assert_eq!((p0.drop_prob, p0.delay_max_ms), (0.0, 0));
        assert_eq!(p1.drop_prob, 0.05);
        assert_eq!(
            (p2.drop_prob, p2.delay_min_ms, p2.delay_max_ms),
            (0.20, 50, 200)
        );
        assert_eq!((p3.ignore_first, p3.answer_fraction), (1, 0.75));
        // The config round trip must preserve the float formatting.
        let text = ResponderConfig {
            iface: "v".into(),
            impairment: Impairment::p1(seed),
            hostile: Hostile::None,
            answers: Vec::new(),
        }
        .to_text();
        assert!(text.contains("drop 0.050"), "text: {text}");
    }
}
