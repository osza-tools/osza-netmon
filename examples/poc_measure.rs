// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// A T-105 boundary binary, exactly like examples/poc_discover.rs: the
// TUI does not exist yet and this measurement tool prints to the
// standard streams by design. The allow is scoped to this file; do not
// copy it anywhere else (AGENTS.md rule 3).
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! T-105 PoC measurement campaign harness (plan §13 T-105, Appendix D;
//! task card §5.1).
//!
//! A dev-only binary that drives the **T-106 netns harness as-is**: it
//! builds the same labs (veth pair + nested `unshare --net` device
//! namespace, plan §11.2) but instead of re-implementing the responder
//! it **re-execs the unmodified T-106 test binary** in `--responder`
//! mode with a generated `responder.conf` (the documented T-106 config
//! format, `tests/netns/config.rs`). The impairment semantics, the
//! seeded RNG and the answer/drop machinery are therefore exactly the
//! ones the S8/S9 baseline tables were produced with; overlapping grid
//! cells reproduce those tables cell-for-cell.
//!
//! Run inside the T-106 wrapper (user namespaces supply
//! `CAP_NET_RAW`/`CAP_NET_ADMIN`; nothing here needs host root):
//!
//! ```text
//! cargo test --locked --all-features --no-run     # builds the netns test binary
//! unshare --user --map-root-user --net bash -c \
//!   'cargo run --locked --example poc_measure -- <subcommand> [flags]'
//! ```
//!
//! Subcommands (one experiment family each; every run writes JSON +
//! Markdown records under `target/t105/`):
//!
//! * `grid` — the ADR-011 matrix: scenario × impairment profile
//!   (P0–P3, S9 variants) × rate (50/100/200 pps) × passes (1/2/3),
//!   N cycles per cell, with per-cycle Appendix D records.
//! * `sender-ip` — interface IP vs `0.0.0.0` (RFC 5227 probe form) via
//!   [`ArpScanner::with_probe_sender_ip`], including what each variant
//!   does to the *device-side* neighbor table.
//! * `unicast` — unicast ARP refresh of known devices
//!   ([`build_arp_request_to`]): cold refresh, warm refresh after a
//!   broadcast sweep, and the stale-MAC (rotation) case that cannot
//!   recover, followed by a broadcast sweep that can.
//! * `late` — a fixed long reply delay that lands pass-1 answers after
//!   the pass-2 snapshot: the T-104 review F-6 "re-probed once"
//!   semantics, made visible in the responder's request log.
//! * `transport` — the interim `ETH_P_ALL` + software-filter cost: the
//!   same scan with a counting wrapper around the production transport
//!   under controlled non-ARP background rates, plus a Python
//!   `AF_PACKET`/`ETH_P_ARP` witness socket that counts what a kernel
//!   EtherType binding would have delivered (the alternative itself
//!   cannot be written without `unsafe` or a new dependency — that is
//!   the ADR-009 question this experiment feeds).
//! * `neighbor` — `/proc/net/arp` (the production source, T-102) vs
//!   netlink `RTM_GETNEIGH` (via `ip neigh`, the same kernel source a
//!   Rust netlink client would read) with a state timeline while real
//!   device→host traffic runs, plus what our own ARP sweeps do and do
//!   not populate.
//! * `observe` — the Owner-network stand-in: a client-isolated Wi-Fi
//!   shape (one answering "gateway", everything else silent) driven
//!   through the T-104 `poc_discover` boundary binary in both modes
//!   (privileged active sweep; `CAP_NET_RAW`-less read-only). The real
//!   Owner session is human-run per plan §13; this validates the same
//!   paths and produces the runbook evidence.
//! * `iface-flip` — the interface going down (and back up) mid-scan:
//!   outcome classification, boundedness, recovery.
//! * `drop-netraw-exec — <cmd>` — drops `CAP_NET_RAW` from every set
//!   (the approved `caps` crate, the S7(a) probe pattern) and execs
//!   `<cmd>`: the read-only-mode driver used by `observe`.
//!
//! Data rules (task card §8): all addresses are RFC 5737 documentation
//! addresses, all synthetic MACs are locally administered `02:…`, no
//! real identifiers are logged, and active probing happens only inside
//! these namespaces.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use osza_netmon::discovery::arp::ArpReplyContext;
use osza_netmon::discovery::arp::ArpScanner;
use osza_netmon::discovery::arp::ArpTransport;
use osza_netmon::discovery::arp::DEFAULT_LISTEN_WINDOW;
use osza_netmon::discovery::arp::DEFAULT_RATE_PPS;
use osza_netmon::discovery::arp::InvalidReply;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::arp::Observation;
use osza_netmon::discovery::arp::ScanCounters;
use osza_netmon::discovery::arp::ScanOutcome;
use osza_netmon::discovery::arp::TransportError;
use osza_netmon::discovery::arp::build_arp_request_to;
use osza_netmon::discovery::arp::parse_arp_reply;
use osza_netmon::discovery::neighbor_table::NeighborSource;
use osza_netmon::discovery::neighbor_table::ProcNeighborTable;
use osza_netmon::discovery::privilege::open_raw_socket;
use osza_netmon::model::ipv4::Ipv4Net;
use osza_netmon::model::mac::MacAddr;
use osza_netmon::net::interfaces::enumerate_interfaces;

/// The T-106 seed base (`tests/netns/rng.rs::seeds::MEASURE_BASE`), so
/// overlapping cells use the same seeds as the S8/S9 baseline.
const MEASURE_BASE: u64 = 0x7EED_1061;

/// How long to wait for lab setup steps (PID file, responder READY).
const SETUP_WAIT: Duration = Duration::from_secs(20);

/// Poll granularity during bounded waits.
const POLL: Duration = Duration::from_millis(20);

/// The UDP port the neighbor experiment's device→host traffic targets
/// (the host side binds and drains it so no ICMP port-unreachable
/// noise is generated — one-way traffic only).
const NEIGHBOR_UDP_PORT: u16 = 39009;

/// Ethernet EtherType ARP (`0x0806`) at frame offsets 12..14 — the
/// software filter position used by the counting wrapper.
const ETHERTYPE_ARP_BE: [u8; 2] = [0x08, 0x06];

// ---------------------------------------------------------------------------
// Small shared utilities (mirrors of the T-106 helpers)
// ---------------------------------------------------------------------------

/// Parses `a.b.c.d/prefix` into an [`Ipv4Net`] (total).
fn parse_cidr(text: &str) -> Result<Ipv4Net, String> {
    let (addr, prefix) = text
        .split_once('/')
        .ok_or_else(|| format!("expected a.b.c.d/prefix, found {text:?}"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| format!("bad address part {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("bad prefix part {prefix:?}"))?;
    Ipv4Net::new(addr, prefix).map_err(|err| format!("bad network: {err}"))
}

/// Reads this process's CPU time (user + system, milliseconds) from
/// `/proc/self/stat` — the Appendix D per-run CPU field. `None` when
/// the file cannot be read or parsed (the measurement reports the gap).
fn process_cpu_ms() -> Option<u64> {
    let mut text = String::new();
    let mut file = fs::File::open("/proc/self/stat").ok()?;
    file.read_to_string(&mut text).ok()?;
    let after = text.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: u64 = fields.get(11).and_then(|value| value.parse().ok())?;
    let stime: u64 = fields.get(12).and_then(|value| value.parse().ok())?;
    // USER_HZ == 100 on Linux.
    Some(((utime + stime) as f64 * 10.0).round() as u64)
}

/// A UTC timestamp without pulling a dependency (`YYYY-MM-DDTHH:MM:SSZ`
/// from `SystemTime`; the same algorithm as the T-106 harness).
fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// JSON string escaping for the free-form record fields.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Locks a mutex, recovering from poisoning (the producer-consumer
/// pattern of `src/discovery/privilege.rs`).
fn lock_or_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Flag parsing (total, hand-rolled like poc_discover; T-402 owns the
// real CLI)
// ---------------------------------------------------------------------------

/// Reads `--key value` from a flat flag list (the key is given without
/// its `--` prefix; the comparison is against the full flag).
fn value_of(args: &[String], key: &str) -> Option<String> {
    let flag = format!("--{key}");
    let mut iter = args.iter();
    while let Some(current) = iter.next() {
        if *current == flag {
            return iter.next().cloned();
        }
    }
    None
}

/// Reads `--key a,b,c` as a list of `T` (total parse; a bad item fails
/// the whole list with a message naming the flag).
fn list_of<T>(
    args: &[String],
    key: &str,
    parse: &dyn Fn(&str) -> Result<T, String>,
) -> Option<Result<Vec<T>, String>> {
    let raw = value_of(args, key)?;
    let mut out = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        match parse(item) {
            Ok(value) => out.push(value),
            Err(err) => return Some(Err(format!("--{key}: {err}"))),
        }
    }
    Some(Ok(out))
}

/// Parses a `u32` flag value.
fn parse_u32(text: &str) -> Result<u32, String> {
    text.parse().map_err(|_| format!("not a number: {text:?}"))
}

/// Parses a `u8` flag value.
fn parse_u8(text: &str) -> Result<u8, String> {
    text.parse().map_err(|_| format!("not a number: {text:?}"))
}

/// Parses a `u64` flag value.
fn parse_u64(text: &str) -> Result<u64, String> {
    text.parse().map_err(|_| format!("not a number: {text:?}"))
}

// ---------------------------------------------------------------------------
// Impairment profiles (Appendix D; the T-106 `Impairment` parameters,
// serialized in the T-106 responder config format)
// ---------------------------------------------------------------------------

/// The impairment parameters of one lab, in the T-106 responder's
/// config vocabulary (`tests/netns/config.rs`). The constructors match
/// `Impairment::none/p1/p2/p3/s9_*` exactly; `fixed_delay` is a T-105
/// addition for the pass-2 snapshot experiment (a delay long enough to
/// land pass-1 replies after the pass-2 snapshot).
#[derive(Debug, Clone, Copy, PartialEq)]
struct ImpairSpec {
    seed: u64,
    drop_prob: f64,
    delay_min_ms: u64,
    delay_max_ms: u64,
    ignore_first: u32,
    answer_fraction: f64,
}

impl ImpairSpec {
    fn base(seed: u64) -> Self {
        Self {
            seed,
            drop_prob: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 0,
            ignore_first: 0,
            answer_fraction: 1.0,
        }
    }

    /// P0 — none.
    fn p0(seed: u64) -> Self {
        Self::base(seed)
    }

    /// P1 — 5% frame loss.
    fn p1(seed: u64) -> Self {
        Self {
            drop_prob: 0.05,
            ..Self::base(seed)
        }
    }

    /// P2 — 20% loss plus 50–200 ms delay/jitter.
    fn p2(seed: u64) -> Self {
        Self {
            drop_prob: 0.20,
            delay_min_ms: 50,
            delay_max_ms: 200,
            ..Self::base(seed)
        }
    }

    /// P3 — sleepy: ignore the first request, answer 75%, 150–250 ms
    /// late.
    fn p3(seed: u64) -> Self {
        Self {
            delay_min_ms: 150,
            delay_max_ms: 250,
            ignore_first: 1,
            answer_fraction: 0.75,
            ..Self::base(seed)
        }
    }

    /// S9 (a): ignore the first two requests, then answer everything.
    fn s9_ignore_first(seed: u64) -> Self {
        Self {
            ignore_first: 2,
            ..Self::base(seed)
        }
    }

    /// S9 (b): answer only half the requests.
    fn s9_fraction(seed: u64) -> Self {
        Self {
            answer_fraction: 0.5,
            ..Self::base(seed)
        }
    }

    /// S9 (c): answer late, 300–500 ms.
    fn s9_late(seed: u64) -> Self {
        Self {
            delay_min_ms: 300,
            delay_max_ms: 500,
            ..Self::base(seed)
        }
    }

    /// T-105 `late` experiment: a fixed `ms` delay, no loss — replies
    /// land after the pass-2 snapshot by construction.
    fn fixed_delay(seed: u64, ms: u64) -> Self {
        Self {
            delay_min_ms: ms,
            delay_max_ms: ms,
            ..Self::base(seed)
        }
    }

    /// The label used in records and tables.
    fn label(&self) -> &'static str {
        if self.drop_prob == 0.05 {
            "P1"
        } else if self.drop_prob == 0.20 {
            "P2"
        } else if self.ignore_first == 2 {
            "S9-ignore-first-2"
        } else if (self.answer_fraction - 0.5).abs() < f64::EPSILON {
            "S9-fraction-0.5"
        } else if self.delay_min_ms == 300 {
            "S9-late-400ms"
        } else if self.ignore_first == 1 {
            "P3"
        } else if self.delay_min_ms == 50 {
            "P2"
        } else if self.delay_min_ms > 0 {
            "fixed-delay"
        } else {
            "P0"
        }
    }

    /// Serializes into the T-106 responder config's impairment keys.
    fn config_lines(&self) -> String {
        format!(
            "seed {}\ndrop {:.3}\ndelay_min_ms {}\ndelay_max_ms {}\nignore_first {}\nanswer_fraction {:.3}\n",
            self.seed,
            self.drop_prob,
            self.delay_min_ms,
            self.delay_max_ms,
            self.ignore_first,
            self.answer_fraction
        )
    }
}

/// One answered address of the responder's answer table.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Answer {
    ip: Ipv4Addr,
    mac: MacAddr,
}

/// Builds the synthetic answer set `(ip, mac)` for a run of addresses,
/// the same generator as the T-106 measurement shapes
/// (`02:00:00:00:01:<last octet>`).
fn answers_from(first: &str, count: u8, mac_salt: u8) -> Result<Vec<Answer>, String> {
    let base: Ipv4Addr = first
        .parse()
        .map_err(|_| format!("bad IP literal {first:?}"))?;
    let mut out = Vec::new();
    for offset in 0..count {
        let octets = base.octets();
        let Some(last) = octets[3].checked_add(offset) else {
            return Err(format!("address run overflows at offset {offset}"));
        };
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], last);
        let mac = MacAddr::from_octets([0x02, 0x00, 0x00, mac_salt, 0x01, last])
            .map_err(|err| format!("bad synthetic MAC for {ip}: {err}"))?;
        out.push(Answer { ip, mac });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The lab (a faithful mirror of tests/netns/lab.rs, driving the T-106
// responder binary as-is)
// ---------------------------------------------------------------------------

/// Device→host UDP traffic the neighbor experiment uses to populate
/// real kernel neighbor state (bound source addresses, host-side port
/// is drained so no ICMP is generated).
struct PreTraffic {
    srcs: Vec<Ipv4Addr>,
    host: Ipv4Addr,
    duration_s: u64,
    interval_ms: u64,
}

/// What one lab needs.
struct LabSpec {
    /// Short interface tag (`v-<tag>a`/`v-<tag>b`; IFNAMSIZ keeps tags
    /// short — the descriptive identity lives in the records).
    tag: String,
    subnet: Ipv4Net,
    kernel_addrs: Vec<Ipv4Addr>,
    answers: Vec<Answer>,
    impairment: ImpairSpec,
    /// Optional fixed MAC for the device-side veth end (the
    /// kernel-answered half's link address; deterministic when the
    /// experiment needs to know it before discovering it).
    peer_mac: Option<MacAddr>,
    /// Optional non-ARP background frame rate from the device side
    /// (transport experiment): `(pps, duration seconds)`.
    background: Option<(u32, u64)>,
    /// Optional device→host UDP traffic (neighbor experiment).
    pre_traffic: Option<PreTraffic>,
}

impl LabSpec {
    fn host_ip(&self) -> Ipv4Addr {
        let octets = self.subnet.network().octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].saturating_add(1))
    }

    fn host_if(&self) -> String {
        format!("v-{}a", self.tag)
    }

    fn peer_if(&self) -> String {
        format!("v-{}b", self.tag)
    }
}

/// A live lab: the scanner-side facts plus teardown handles.
struct Lab {
    host_if: String,
    scope: Ipv4Net,
    our_ip: Ipv4Addr,
    our_mac: MacAddr,
    /// The device-side veth's MAC when the lab pinned it (`None`
    /// otherwise; the kernel half then answers with a random address).
    device_mac: Option<MacAddr>,
    log_path: PathBuf,
    artifacts: PathBuf,
    child_pid: u32,
    child: Option<Child>,
    /// Set by the first teardown (the explicit call and `Drop` must not
    /// both run the delete).
    torn_down: bool,
}

impl Lab {
    /// Builds the lab (the T-106 recipe; see the module docs).
    fn build(spec: &LabSpec) -> Result<Lab, String> {
        let artifacts = artifacts_dir(&spec.tag);
        let _ = fs::remove_dir_all(&artifacts);
        fs::create_dir_all(&artifacts)
            .map_err(|err| format!("lab {}: creating {}: {err}", spec.tag, artifacts.display()))?;

        let host_if = spec.host_if();
        let peer_if = spec.peer_if();
        let host_ip = spec.host_ip();
        let prefix = spec.subnet.prefix_len();

        run_ip(
            &[
                "link", "add", &host_if, "type", "veth", "peer", "name", &peer_if,
            ],
            &format!("lab {}: creating the veth pair", spec.tag),
        )?;
        run_ip(
            &[
                "addr",
                "add",
                &format!("{host_ip}/{prefix}"),
                "dev",
                &host_if,
            ],
            &format!("lab {}: configuring {host_if}", spec.tag),
        )?;
        run_ip(
            &["link", "set", &host_if, "addrgenmode", "none"],
            &format!("lab {}: disabling IPv6 generation on {host_if}", spec.tag),
        )?;
        run_ip(
            &["link", "set", &host_if, "up"],
            &format!("lab {}: bringing {host_if} up", spec.tag),
        )?;
        // A pinned device-side MAC, when the experiment needs the
        // kernel half's link address before discovering it (the
        // unicast-refresh phases).
        if let Some(peer_mac) = spec.peer_mac {
            run_ip(
                &["link", "set", &peer_if, "address", &peer_mac.to_string()],
                &format!("lab {}: pinning {peer_if} address", spec.tag),
            )?;
        }

        // The responder config (T-106 format, writer side).
        let config_path = artifacts.join("responder.conf");
        let log_path = artifacts.join("responder.log");
        let mut config = String::new();
        config.push_str("# osza-netmon netns responder config v1\n");
        config.push_str(&format!("iface {peer_if}\n"));
        config.push_str(&spec.impairment.config_lines());
        config.push_str("hostile none\n");
        for answer in &spec.answers {
            config.push_str(&format!("answer {} {}\n", answer.ip, answer.mac));
        }
        fs::write(&config_path, config)
            .map_err(|err| format!("lab {}: writing config: {err}", spec.tag))?;

        // Optional device-side helpers (Python; dev-only measurement
        // tooling, no project-code constraints).
        let mut extra_lines = String::new();
        if let Some((rate, duration)) = spec.background {
            let script = artifacts.join("bg.py");
            fs::write(&script, BACKGROUND_SENDER_PY)
                .map_err(|err| format!("lab {}: writing bg.py: {err}", spec.tag))?;
            let bg_log = artifacts.join("bg.log");
            extra_lines.push_str(&format!(
                "timeout 600 python3 {script} {peer_if} {rate} {duration} >>{log} 2>&1 &\n",
                script = script.display(),
                log = bg_log.display()
            ));
        }
        if let Some(pre) = &spec.pre_traffic {
            let script = artifacts.join("pretraffic.py");
            fs::write(&script, PRE_TRAFFIC_PY)
                .map_err(|err| format!("lab {}: writing pretraffic.py: {err}", spec.tag))?;
            let srcs = pre
                .srcs
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let pre_log = artifacts.join("pre.log");
            extra_lines.push_str(&format!(
                "timeout 600 python3 {script} {host} {port} {dur} {interval} {srcs} >>{log} 2>&1 &\n",
                script = script.display(),
                host = pre.host,
                port = NEIGHBOR_UDP_PORT,
                dur = pre.duration_s,
                interval = pre.interval_ms,
                log = pre_log.display()
            ));
        }

        // The device-side child: nested `unshare --net`, bash config
        // script, then `exec` of the T-106 responder (as-is).
        let pid_path = artifacts.join("child.pid");
        let exe = netns_test_binary()?;
        let mut script = String::from(
            "set -e\necho $$ > \"$OZ_PIDFILE\"\n\
             i=0\n\
             while [ \"$i\" -lt 500 ] && ! ip link show \"$OZ_IFACE\" >/dev/null 2>&1; do\n\
             \tsleep 0.02; i=$((i+1))\n\
             done\n\
             ip link show \"$OZ_IFACE\" >/dev/null 2>&1 || { echo 'device veth never appeared' >&2; exit 3; }\n\
             ip link set lo up\n\
             ip link set \"$OZ_IFACE\" addrgenmode none\n\
             ip link set \"$OZ_IFACE\" up\n",
        );
        for addr in &spec.kernel_addrs {
            script.push_str(&format!(
                "ip addr add \"{addr}/{prefix}\" dev \"$OZ_IFACE\"\n"
            ));
        }
        script.push_str(&extra_lines);
        script.push_str("exec \"$OZ_EXE\" --responder --config \"$OZ_CONFIG\" --log \"$OZ_LOG\"\n");

        let mut child = Command::new("unshare")
            .arg("--net")
            .arg("bash")
            .arg("-c")
            .arg(&script)
            .env("OZ_IFACE", &peer_if)
            .env("OZ_PIDFILE", &pid_path)
            .env("OZ_CONFIG", &config_path)
            .env("OZ_LOG", &log_path)
            .env("OZ_EXE", &exe)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|err| format!("lab {}: spawning the device namespace: {err}", spec.tag))?;

        let pid = wait_for_pid_file(&pid_path, &spec.tag, &mut child)?;
        run_ip(
            &["link", "set", &peer_if, "netns", &pid.to_string()],
            &format!(
                "lab {}: moving {peer_if} into the device namespace",
                spec.tag
            ),
        )?;
        wait_for_ready(&log_path, &spec.tag, &mut child)?;

        // Our own interface facts through the production enumerator.
        let info = enumerate_interfaces()
            .into_iter()
            .find(|info| info.name() == host_if)
            .ok_or_else(|| format!("lab {}: {host_if} not enumerated", spec.tag))?;
        let our_mac = info
            .mac()
            .ok_or_else(|| format!("lab {}: {host_if} has no MAC", spec.tag))?;
        let our_ip = info
            .ipv4()
            .ok_or_else(|| format!("lab {}: {host_if} has no IPv4 address", spec.tag))?;
        let _ = fs::write(artifacts.join("child-pid.txt"), pid.to_string());

        Ok(Lab {
            host_if,
            scope: spec.subnet,
            our_ip,
            our_mac,
            device_mac: spec.peer_mac,
            log_path,
            artifacts,
            child_pid: pid,
            child: Some(child),
            torn_down: false,
        })
    }

    /// The parsed responder receive log (fresh read).
    fn rxlog(&self) -> RxSummary {
        RxSummary::read(&self.log_path)
    }

    /// The device-side neighbor table, read through `/proc/<pid>/net/arp`
    /// (the device namespace is the child's).
    fn device_arp_rows(&self) -> String {
        let path = format!("/proc/{}/net/arp", self.child_pid);
        fs::read_to_string(path).unwrap_or_default()
    }

    /// Deletes the host-side veth end (both ends of the pair vanish
    /// with it) and kills the device-side child — in that order, so the
    /// explicit delete always targets a live interface (killing the
    /// child first would destroy the pair and make the delete fail with
    /// a benign but noisy "Cannot find device"). Idempotent: the first
    /// call wins, `Drop` and explicit calls agree.
    fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_if])
            .status();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Runs `ip` and fails with `context` on a non-zero exit.
fn run_ip(args: &[&str], context: &str) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| format!("{context}: spawning ip: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{context}: ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Waits (bounded) for the child's PID file; an early child exit fails
/// fast.
fn wait_for_pid_file(path: &Path, tag: &str, child: &mut Child) -> Result<u32, String> {
    let deadline = Instant::now() + SETUP_WAIT;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return Ok(pid);
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "lab {tag}: the device-side child exited early with {status}"
            ));
        }
        thread::sleep(POLL);
    }
    Err(format!(
        "lab {tag}: the device namespace never published its PID"
    ))
}

/// Waits (bounded) for the responder's READY line.
fn wait_for_ready(log_path: &Path, tag: &str, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + SETUP_WAIT;
    let mut last_seen = String::new();
    while Instant::now() < deadline {
        if let Ok(log) = fs::read_to_string(log_path) {
            if log.contains("READY ") {
                return Ok(());
            }
            if log.contains("fatal") {
                return Err(format!("lab {tag}: the responder failed to start: {log}"));
            }
            last_seen = log;
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "lab {tag}: the device-side child exited early with {status}; log:\n{last_seen}"
            ));
        }
        thread::sleep(POLL);
    }
    Err(format!(
        "lab {tag}: the responder never became ready; log so far:\n{last_seen}"
    ))
}

/// The artifact directory of a lab under `target/t105/`.
fn artifacts_dir(tag: &str) -> PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    dir.push("target");
    dir.push("t105");
    dir.push(tag);
    dir
}

/// Locates the T-106 netns test binary (the responder) — `OSZA_NETNS_BIN`
/// wins, otherwise the newest `netns-*` executable next to this example
/// (`target/debug/deps/`) is used.
fn netns_test_binary() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("OSZA_NETNS_BIN")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let deps = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .and_then(|examples| examples.parent().map(Path::to_path_buf))
        .map(|target| target.join("deps"))
        .unwrap_or_else(|| PathBuf::from("target/debug/deps"));
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries =
        fs::read_dir(&deps).map_err(|err| format!("listing {}: {err}", deps.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("netns-") || name.ends_with(".d") || name.ends_with(".dSYM") {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let modified = meta.modified().ok();
        let newer = best
            .as_ref()
            .and_then(|(best_time, _)| modified.filter(|time| time > best_time))
            .or(modified);
        if let Some(time) = newer {
            best = Some((time, path));
        }
    }
    best.map(|(_, path)| path).ok_or_else(|| {
        format!(
            "the T-106 netns test binary was not found under {}; \
             run `cargo test --locked --all-features --no-run` first, \
             or set OSZA_NETNS_BIN",
            deps.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Responder log parsing (the RX/TX/DROP subset this campaign needs)
// ---------------------------------------------------------------------------

/// One received-request record (`RX` lines with `op=1`).
#[derive(Debug, Clone, PartialEq)]
struct RxRequest {
    t: u64,
    src: Option<String>,
    dst: Option<String>,
    sip: Option<Ipv4Addr>,
    tip: Option<Ipv4Addr>,
}

/// The parsed summary of one responder log.
#[derive(Debug, Default, Clone)]
struct RxSummary {
    ready: bool,
    rx_total: usize,
    tx_total: usize,
    drops: usize,
    /// ARP requests in arrival order (any source).
    requests: Vec<RxRequest>,
    /// Replies the responder sent (`TX kind=answer…` count).
    answers: usize,
}

impl RxSummary {
    /// Total parse of the log: malformed lines are skipped (counted in
    /// `rx_total` only when they start with `RX`), never panic.
    fn read(path: &Path) -> RxSummary {
        let mut summary = RxSummary::default();
        let Ok(text) = fs::read_to_string(path) else {
            return summary;
        };
        for line in text.lines() {
            if line.starts_with("READY ") {
                summary.ready = true;
            } else if let Some(rest) = line.strip_prefix("RX ") {
                summary.rx_total += 1;
                if field(line, "op=").as_deref() == Some("1") {
                    summary.requests.push(RxRequest {
                        t: number(rest, "t=").unwrap_or(0),
                        src: field(line, "src="),
                        dst: field(line, "dst="),
                        sip: field(line, "sip=").and_then(|v| v.parse().ok()),
                        tip: field(line, "tip=").and_then(|v| v.parse().ok()),
                    });
                }
            } else if let Some(rest) = line.strip_prefix("TX ") {
                summary.tx_total += 1;
                if rest.contains("kind=answer") {
                    summary.answers += 1;
                }
            } else if line.starts_with("DROP ") {
                summary.drops += 1;
            }
        }
        summary
    }

    /// Requests per target address (the F-6 "re-probed once" evidence).
    fn requests_per_target(&self) -> BTreeMap<Ipv4Addr, u32> {
        let mut counts: BTreeMap<Ipv4Addr, u32> = BTreeMap::new();
        for request in &self.requests {
            if let Some(tip) = request.tip {
                *counts.entry(tip).or_insert(0) += 1;
            }
        }
        counts
    }

    /// The requests of one Ethernet source, for the unicast-refresh
    /// phases (the scanner's own frames carry its MAC as the source).
    fn requests_from(&self, src_mac: &MacAddr) -> Vec<RxRequest> {
        self.requests
            .iter()
            .filter(|request| {
                request
                    .src
                    .as_deref()
                    .and_then(|src| src.parse::<MacAddr>().ok())
                    .is_some_and(|src| src == *src_mac)
            })
            .cloned()
            .collect()
    }
}

/// `Some(value)` of `key=` in a log line, cut at the next whitespace
/// (space, newline, tab — the witness's stdout is parsed whole, not
/// per line).
fn field(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = line.get(start..)?;
    let end = rest
        .find(|character: char| character.is_whitespace())
        .unwrap_or(rest.len());
    rest.get(..end).map(str::to_owned)
}

/// The numeric value of `key=` in a log line.
fn number(line: &str, key: &str) -> Option<u64> {
    field(line, key).and_then(|value| value.parse().ok())
}

// ---------------------------------------------------------------------------
// Device-side Python helpers (dev-only measurement tooling; written into
// the lab artifacts and run inside the device namespace)
// ---------------------------------------------------------------------------

/// Sends non-ARP Ethernet frames (EtherType `0x1234`, 60 bytes,
/// broadcast destination, synthetic `02:…` source) at a fixed rate
/// until the duration ends or the interface dies.
const BACKGROUND_SENDER_PY: &str = r#"import socket, sys, time
iface, rate, dur = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
frame = bytes.fromhex("ffffffffffff") + bytes.fromhex("0200 00bb 0001".replace(" ", "")) + bytes.fromhex("1234") + bytes(46)
interval = 1.0 / rate if rate > 0 else 0.0
end = time.time() + dur
sent = 0
while time.time() < end:
    try:
        s.send(frame)
    except OSError:
        break
    sent += 1
    if interval:
        time.sleep(interval)
print("BG_SENT", sent)
"#;

/// Sends one-way UDP datagrams to the host from each bound source
/// address (the neighbor experiment's real IP traffic).
const PRE_TRAFFIC_PY: &str = r#"import socket, sys, time
host, port, dur, interval = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]) / 1000.0
addrs = sys.argv[5:]
socks = []
for a in addrs:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((a, 0))
    socks.append(s)
end = time.time() + dur
while time.time() < end:
    for s in socks:
        try:
            s.sendto(b"t105", (host, port))
        except OSError:
            pass
    time.sleep(interval)
"#;

/// Counts ARP frames an `AF_PACKET` socket bound with `ETH_P_ARP`
/// receives, by packet type (0 = incoming/HOST, 4 = OUTGOING) — the
/// kernel-level EtherType filter witness.
const ARP_WITNESS_PY: &str = r#"import socket, sys, time
iface, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((iface, 0))
s.settimeout(0.2)
end = time.time() + secs
counts = {}
total = 0
while time.time() < end:
    try:
        data, (ifname, proto, pkttype, hatype, addr) = s.recvfrom(4096)
    except socket.timeout:
        continue
    counts[pkttype] = counts.get(pkttype, 0) + 1
    total += 1
print("WITNESS total=%d in=%d outgoing=%d" % (total, counts.get(0, 0), counts.get(4, 0)))
"#;

// ---------------------------------------------------------------------------
// Scenario shapes (mirrors of the T-106 measurement shapes, so
// overlapping cells are directly comparable)
// ---------------------------------------------------------------------------

/// One measurement scenario shape: the lab topology plus the
/// known-device ground truth.
struct Shape {
    name: &'static str,
    subnet: &'static str,
    kernel_addrs: Vec<Ipv4Addr>,
    answers: Vec<Answer>,
    known: Vec<Ipv4Addr>,
    note: &'static str,
}

impl Shape {
    /// S1: the mixed lab — 10 kernel-answered + 10 helper-answered.
    fn s1() -> Result<Shape, String> {
        let answers = answers_from("192.0.2.12", 10, 0x00)?;
        let kernel_addrs: Vec<Ipv4Addr> = (2u8..=11)
            .map(|host| Ipv4Addr::new(192, 0, 2, host))
            .collect();
        let mut known = kernel_addrs.clone();
        known.extend(answers.iter().map(|answer| answer.ip));
        Ok(Shape {
            name: "S1 (20 mixed)",
            subnet: "192.0.2.0/24",
            kernel_addrs,
            answers,
            known,
            note: "10 kernel-answered (unimpaired) + 10 helper-answered (impaired)",
        })
    }

    /// S2: a /24 with 250 helper-answered devices (all impaired).
    fn s2() -> Result<Shape, String> {
        let answers = answers_from("198.51.100.2", 250, 0x00)?;
        Ok(Shape {
            name: "S2 (250 addresses)",
            subnet: "198.51.100.0/24",
            kernel_addrs: Vec::new(),
            known: answers.iter().map(|answer| answer.ip).collect(),
            answers,
            note: "250 helper-answered (all impaired by the profile)",
        })
    }

    /// S4: proxy ARP — 12 addresses behind one synthetic MAC.
    fn s4() -> Result<Shape, String> {
        let proxy_mac: MacAddr = "02:00:00:00:00:99"
            .parse()
            .map_err(|err| format!("bad proxy MAC: {err}"))?;
        let answers = answers_from("203.0.113.146", 12, 0x00)?
            .into_iter()
            .map(|mut answer| {
                answer.mac = proxy_mac;
                answer
            })
            .collect::<Vec<_>>();
        Ok(Shape {
            name: "S4 (proxy ARP)",
            subnet: "203.0.113.144/28",
            kernel_addrs: Vec::new(),
            known: answers.iter().map(|answer| answer.ip).collect(),
            answers,
            note: "12 IPs behind one MAC (02:00:00:00:00:99)",
        })
    }

    /// S9: 12 helper-answered sleepy devices.
    fn s9() -> Result<Shape, String> {
        let answers = answers_from("203.0.113.162", 12, 0x00)?;
        Ok(Shape {
            name: "S9 (sleepy hosts)",
            subnet: "203.0.113.160/28",
            kernel_addrs: Vec::new(),
            known: answers.iter().map(|answer| answer.ip).collect(),
            answers,
            note: "12 helper-answered; the S9 parameter variants",
        })
    }

    /// The lab spec of this shape under `impairment`, with a short
    /// unique interface tag.
    fn lab_spec(&self, tag: String, impairment: ImpairSpec) -> Result<LabSpec, String> {
        Ok(LabSpec {
            tag,
            subnet: parse_cidr(self.subnet)?,
            kernel_addrs: self.kernel_addrs.clone(),
            answers: self.answers.clone(),
            impairment,
            peer_mac: None,
            background: None,
            pre_traffic: None,
        })
    }
}

/// Resolves a scenario name to its shape (the grid vocabulary).
fn shape_by_name(name: &str) -> Result<Shape, String> {
    match name {
        "s1" => Shape::s1(),
        "s2" => Shape::s2(),
        "s4" => Shape::s4(),
        "s9-ignore-first-2" | "s9-fraction-0.5" | "s9-late-400ms" => Shape::s9(),
        other => Err(format!(
            "unknown scenario {other:?} (expected s1, s2, s4, s9-ignore-first-2, \
             s9-fraction-0.5, s9-late-400ms)"
        )),
    }
}

/// The impairment profile under the T-106 seed scheme
/// (`MEASURE_BASE + profile index`; S9 variants use `+100 + index`).
fn profile_for(profile: &str) -> Result<ImpairSpec, String> {
    match profile {
        "p0" => Ok(ImpairSpec::p0(MEASURE_BASE)),
        "p1" => Ok(ImpairSpec::p1(MEASURE_BASE + 1)),
        "p2" => Ok(ImpairSpec::p2(MEASURE_BASE + 2)),
        "p3" => Ok(ImpairSpec::p3(MEASURE_BASE + 3)),
        "s9-ignore-first-2" => Ok(ImpairSpec::s9_ignore_first(MEASURE_BASE + 100)),
        "s9-fraction-0.5" => Ok(ImpairSpec::s9_fraction(MEASURE_BASE + 101)),
        "s9-late-400ms" => Ok(ImpairSpec::s9_late(MEASURE_BASE + 102)),
        other => Err(format!(
            "unknown profile {other:?} (expected p0, p1, p2, p3, s9-ignore-first-2, \
             s9-fraction-0.5, s9-late-400ms)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Records (Appendix D per-run fields, T-106-compatible + T-105 extras)
// ---------------------------------------------------------------------------

/// One cycle's record. The T-106 fields keep their exact names so
/// baseline and campaign records can be diffed mechanically; the T-105
/// extensions are nullable.
#[derive(Debug, Clone, Default)]
struct RunRecord {
    experiment: String,
    scenario: String,
    variant: String,
    cycle: u32,
    seed: u64,
    date: String,
    network_type: &'static str,
    scope_size: u32,
    mode: &'static str,
    transport: String,
    rate_pps: u32,
    passes: u8,
    sender_ip_variant: &'static str,
    known_devices: usize,
    discovered_this_cycle: usize,
    discovered_cumulative: usize,
    recall_cumulative_pct: f64,
    extras: usize,
    time_to_first_ms: Option<u64>,
    sweep_duration_ms: Option<u64>,
    packets_sent: u64,
    send_errors: u64,
    replies_accepted: u64,
    duplicates: u64,
    cap_dropped: u64,
    rejected_by_reason: Vec<(String, u64)>,
    outcome: String,
    scan_elapsed_ms: u128,
    cpu_ms: Option<u64>,
    responder_drops: u64,
    impairment_mechanism: &'static str,
    // T-105 extensions (nullable in JSON).
    transport_frames_total: Option<u64>,
    transport_non_arp: Option<u64>,
    transport_arp: Option<u64>,
    witness_arp_in: Option<u64>,
    witness_outgoing: Option<u64>,
    notes: String,
}

/// Minimal, dependency-free JSON emitter for the records array (the
/// T-106 schema plus the nullable T-105 extensions).
fn records_to_json(experiment: &str, records: &[RunRecord]) -> String {
    let mut out = String::from("{\n  \"run\": {\n");
    out.push_str("    \"harness\": \"osza-netmon T-105 poc_measure\",\n");
    out.push_str(&format!(
        "    \"experiment\": {},\n",
        json_string(experiment)
    ));
    out.push_str(&format!("    \"date\": \"{}\",\n", now_utc()));
    out.push_str("    \"responder\": \"T-106 netns test binary, --responder mode (as-is)\",\n");
    out.push_str("    \"impairment_mechanism\": \"helper responder (T-106 seeds)\"\n");
    out.push_str("  },\n  \"records\": [\n");
    for (index, record) in records.iter().enumerate() {
        out.push_str("    {\n");
        let optional = |value: Option<u64>| {
            value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".to_owned())
        };
        let fields: Vec<(String, String)> = vec![
            ("experiment".into(), json_string(&record.experiment)),
            ("scenario".into(), json_string(&record.scenario)),
            ("variant".into(), json_string(&record.variant)),
            ("cycle".into(), record.cycle.to_string()),
            ("seed".into(), record.seed.to_string()),
            ("date".into(), json_string(&record.date)),
            ("network_type".into(), json_string(record.network_type)),
            ("scope_size".into(), record.scope_size.to_string()),
            ("mode".into(), json_string(record.mode)),
            ("transport".into(), json_string(&record.transport)),
            ("rate_pps".into(), record.rate_pps.to_string()),
            ("passes".into(), record.passes.to_string()),
            (
                "sender_ip_variant".into(),
                json_string(record.sender_ip_variant),
            ),
            ("known_devices".into(), record.known_devices.to_string()),
            (
                "discovered_this_cycle".into(),
                record.discovered_this_cycle.to_string(),
            ),
            (
                "discovered_cumulative".into(),
                record.discovered_cumulative.to_string(),
            ),
            (
                "recall_cumulative_pct".into(),
                format!("{:.2}", record.recall_cumulative_pct),
            ),
            ("extras".into(), record.extras.to_string()),
            ("time_to_first_ms".into(), optional(record.time_to_first_ms)),
            (
                "sweep_duration_ms".into(),
                optional(record.sweep_duration_ms),
            ),
            ("packets_sent".into(), record.packets_sent.to_string()),
            ("send_errors".into(), record.send_errors.to_string()),
            (
                "replies_accepted".into(),
                record.replies_accepted.to_string(),
            ),
            ("duplicates".into(), record.duplicates.to_string()),
            ("cap_dropped".into(), record.cap_dropped.to_string()),
            ("outcome".into(), json_string(&record.outcome)),
            ("scan_elapsed_ms".into(), record.scan_elapsed_ms.to_string()),
            ("cpu_ms".into(), optional(record.cpu_ms)),
            ("responder_drops".into(), record.responder_drops.to_string()),
            (
                "impairment_mechanism".into(),
                json_string(record.impairment_mechanism),
            ),
            (
                "transport_frames_total".into(),
                optional(record.transport_frames_total),
            ),
            (
                "transport_non_arp".into(),
                optional(record.transport_non_arp),
            ),
            ("transport_arp".into(), optional(record.transport_arp)),
            ("witness_arp_in".into(), optional(record.witness_arp_in)),
            ("witness_outgoing".into(), optional(record.witness_outgoing)),
            ("notes".into(), json_string(&record.notes)),
        ];
        let mut fields = fields;
        if record
            .rejected_by_reason
            .iter()
            .any(|(_, count)| *count > 0)
        {
            let entries: Vec<String> = record
                .rejected_by_reason
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(name, count)| {
                    format!(
                        "{{\"reason\": {}, \"count\": {}}}",
                        json_string(name),
                        count
                    )
                })
                .collect();
            fields.push((
                "rejected_by_reason".into(),
                format!("[{}]", entries.join(", ")),
            ));
        } else {
            fields.push(("rejected_by_reason".into(), "[]".into()));
        }
        for (position, (key, value)) in fields.iter().enumerate() {
            out.push_str(&format!("      \"{key}\": {value}"));
            if position + 1 < fields.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("    }");
        if index + 1 < records.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

/// Writes the JSON and Markdown artifacts of one experiment and returns
/// their paths for the console line.
fn write_artifacts(experiment: &str, json: &str, markdown: &str) -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    dir.push("target");
    dir.push("t105");
    fs::create_dir_all(&dir).map_err(|err| format!("creating {}: {err}", dir.display()))?;
    let json_path = dir.join(format!("{experiment}.json"));
    let md_path = dir.join(format!("{experiment}.md"));
    fs::write(&json_path, json).map_err(|err| format!("writing {}: {err}", json_path.display()))?;
    fs::write(&md_path, markdown).map_err(|err| format!("writing {}: {err}", md_path.display()))?;
    Ok(json_path)
}

// ---------------------------------------------------------------------------
// The counting transport wrapper (the ETH_P_ALL cost instrumentation)
// ---------------------------------------------------------------------------

/// Per-scan transport frame tallies (AtomicU64: two scanner threads).
#[derive(Default)]
struct TransportCounts {
    frames_total: AtomicU64,
    non_arp: AtomicU64,
    arp: AtomicU64,
}

impl TransportCounts {
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.frames_total.load(Ordering::Relaxed),
            self.non_arp.load(Ordering::Relaxed),
            self.arp.load(Ordering::Relaxed),
        )
    }
}

/// An [`ArpTransport`] wrapper that counts what the underlying
/// production socket delivers, by EtherType — the measured input of the
/// `ETH_P_ALL` + software-filter cost model (the scanner's own filter
/// still runs; this changes nothing about the data path).
struct CountingTransport {
    inner: LinuxArpTransport,
    counts: Arc<TransportCounts>,
}

impl ArpTransport for CountingTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        self.inner.send(frame)
    }

    fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let frame = self.inner.recv(timeout)?;
        if let Some(bytes) = &frame {
            self.counts.frames_total.fetch_add(1, Ordering::Relaxed);
            if bytes.get(12..14) == Some(&ETHERTYPE_ARP_BE) {
                self.counts.arp.fetch_add(1, Ordering::Relaxed);
            } else {
                self.counts.non_arp.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(frame)
    }
}

// ---------------------------------------------------------------------------
// Scan drivers
// ---------------------------------------------------------------------------

/// What one scanner run produced, plus the T-105 timing facts.
struct ScanFacts {
    counters: ScanCounters,
    outcome: ScanOutcome,
    observations: Vec<Observation>,
    time_to_first_ms: Option<u64>,
    elapsed_ms: u128,
    cpu_ms: Option<u64>,
}

/// Runs one scan through `scanner`, collecting observations and timing
/// the first arrival (the measure.rs pattern).
fn run_scan(scanner: &ArpScanner, passes: u8, rate: u32, listen: Duration) -> ScanFacts {
    let collected: Mutex<Vec<Observation>> = Mutex::new(Vec::new());
    let first_seen: Mutex<Option<Instant>> = Mutex::new(None);
    let started = Instant::now();
    let sink = |observation: Observation| {
        let mut first = lock_or_recover(&first_seen);
        if first.is_none() {
            *first = Some(Instant::now());
        }
        lock_or_recover(&collected).push(observation);
    };
    let cpu_before = process_cpu_ms();
    let result = scanner.scan_with_sink(
        passes,
        rate,
        listen,
        Arc::new(AtomicBool::new(false)),
        &sink,
    );
    let cpu_after = process_cpu_ms();
    let observations = std::mem::take(&mut *lock_or_recover(&collected));
    let first = lock_or_recover(&first_seen).take();
    ScanFacts {
        counters: result.counters,
        outcome: result.outcome,
        observations,
        time_to_first_ms: first.map(|at| at.duration_since(started).as_millis() as u64),
        elapsed_ms: started.elapsed().as_millis(),
        cpu_ms: match (cpu_before, cpu_after) {
            (Some(before), Some(after)) if after >= before => Some(after - before),
            _ => None,
        },
    }
}

/// The 14 T-103 rejection tallies (name → count), zero entries included
/// so records are diffable.
fn rejection_tallies(counters: &ScanCounters) -> Vec<(String, u64)> {
    let sample = Ipv4Addr::new(203, 0, 113, 200);
    let reasons: [(&str, InvalidReply); 14] = [
        (
            "truncated",
            InvalidReply::Truncated {
                needed: 42,
                found: 0,
            },
        ),
        (
            "wrong_ether_type",
            InvalidReply::WrongEtherType { found: 0 },
        ),
        (
            "wrong_hardware_type",
            InvalidReply::WrongHardwareType { found: 0 },
        ),
        (
            "wrong_protocol_type",
            InvalidReply::WrongProtocolType { found: 0 },
        ),
        (
            "wrong_hardware_length",
            InvalidReply::WrongHardwareLength { found: 0 },
        ),
        (
            "wrong_protocol_length",
            InvalidReply::WrongProtocolLength { found: 0 },
        ),
        ("wrong_opcode", InvalidReply::WrongOpcode { found: 1 }),
        ("mac_mismatch", InvalidReply::MacMismatch),
        (
            "invalid_mac",
            InvalidReply::InvalidMac {
                reason: osza_netmon::model::mac::MacAddrParseError::MulticastAddress,
            },
        ),
        ("out_of_scope", InvalidReply::OutOfScope { found: sample }),
        (
            "network_address",
            InvalidReply::NetworkAddress { found: sample },
        ),
        (
            "broadcast_address",
            InvalidReply::BroadcastAddress { found: sample },
        ),
        ("own_address", InvalidReply::OwnAddress),
        (
            "not_solicited",
            InvalidReply::NotSolicited { found: sample },
        ),
    ];
    reasons
        .iter()
        .map(|(name, reason)| ((*name).to_owned(), counters.replies.rejected_with(reason)))
        .collect()
}

/// One unicast-refresh phase: paced unicast requests to known
/// `(ip, mac)` pairs through a shared transport, replies validated by
/// the production parser (T-105's ADR-011 experiment). Arrival times
/// (ms since phase start) are recorded per reply; the responder log
/// carries the authoritative per-frame timestamps.
struct RefreshFacts {
    sent: u64,
    send_errors: u64,
    /// Accepted replies: `(ip, mac, arrival_ms)`.
    replies: Vec<(Ipv4Addr, MacAddr, u64)>,
    rejected: u64,
    elapsed_ms: u128,
    cpu_ms: Option<u64>,
}

fn unicast_refresh(
    transport: &Arc<dyn ArpTransport>,
    scope: Ipv4Net,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    targets: &[(Ipv4Addr, MacAddr)],
    rate_pps: u32,
    listen_window: Duration,
) -> RefreshFacts {
    let started = Instant::now();
    let interval = Duration::from_millis(1000 / u64::from(rate_pps.max(1)));
    let solicited: HashSet<Ipv4Addr> = targets.iter().map(|(ip, _)| *ip).collect();
    let collected: Arc<Mutex<Vec<(Ipv4Addr, MacAddr, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let rejected = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let receiver = {
        let transport = Arc::clone(transport);
        let collected = Arc::clone(&collected);
        let rejected = Arc::clone(&rejected);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                match transport.recv(Duration::from_millis(20)) {
                    Ok(Some(frame)) => {
                        if frame.get(12..14) != Some(&ETHERTYPE_ARP_BE) {
                            continue;
                        }
                        let arrival_ms = started.elapsed().as_millis() as u64;
                        let outcome = {
                            let ctx = ArpReplyContext::new(our_mac, our_ip, scope, &solicited);
                            parse_arp_reply(&frame, &ctx)
                        };
                        match outcome {
                            Ok(reply) => lock_or_recover(&collected).push((
                                reply.sender_ip,
                                reply.sender_mac,
                                arrival_ms,
                            )),
                            Err(_) => {
                                rejected.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })
    };

    let cpu_before = process_cpu_ms();
    let mut sent = 0u64;
    let mut send_errors = 0u64;
    let mut next_deadline: Option<Instant> = None;
    for (ip, mac) in targets {
        if let Some(deadline) = next_deadline {
            let now = Instant::now();
            if deadline > now {
                thread::sleep(deadline - now);
            }
        }
        let frame = build_arp_request_to(*mac, our_mac, our_ip, *ip);
        match transport.send(&frame) {
            Ok(()) => sent += 1,
            Err(_) => send_errors += 1,
        }
        let now = Instant::now();
        let base = next_deadline
            .filter(|previous| *previous > now)
            .unwrap_or(now);
        next_deadline = Some(base + interval);
    }
    // Listen window after the last send, then stop the receiver.
    thread::sleep(listen_window);
    done.store(true, Ordering::Release);
    let _ = receiver.join();
    let cpu_after = process_cpu_ms();
    RefreshFacts {
        sent,
        send_errors,
        replies: std::mem::take(&mut *lock_or_recover(&collected)),
        rejected: rejected.load(Ordering::Relaxed),
        elapsed_ms: started.elapsed().as_millis(),
        cpu_ms: match (cpu_before, cpu_after) {
            (Some(before), Some(after)) if after >= before => Some(after - before),
            _ => None,
        },
    }
}

// ---------------------------------------------------------------------------
// Experiment: grid (the ADR-011 rate × passes × profile matrix)
// ---------------------------------------------------------------------------

/// `grid` — for every (scenario, profile, rate, passes) cell: one fresh
/// lab, `--cycles` scans, one Appendix D record per cycle.
fn cmd_grid(args: &[String]) -> Result<(), String> {
    let scenarios = match list_of(args, "scenarios", &|s| {
        shape_by_name(s).map(|_| s.to_owned())
    }) {
        Some(list) => list?,
        None => vec!["s1".to_owned(), "s2".to_owned(), "s4".to_owned()],
    };
    let profiles = match list_of(args, "profiles", &|s| profile_for(s).map(|_| s.to_owned())) {
        Some(list) => list?,
        None => vec![
            "p0".to_owned(),
            "p1".to_owned(),
            "p2".to_owned(),
            "p3".to_owned(),
        ],
    };
    let rates = match list_of(args, "rates", &parse_u32) {
        Some(list) => list?,
        None => vec![50, 100, 200],
    };
    let passes = match list_of(args, "passes", &parse_u8) {
        Some(list) => list?,
        None => vec![1, 2, 3],
    };
    let cycles: u32 = value_of(args, "cycles")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let name = value_of(args, "name").unwrap_or_else(|| "grid".to_owned());

    let mut records: Vec<RunRecord> = Vec::new();
    let mut failures = 0usize;
    let mut cell_index = 0usize;
    for scenario_name in &scenarios {
        let shape = shape_by_name(scenario_name)?;
        for profile_name in &profiles {
            let impairment = profile_for(profile_name)?;
            for rate in &rates {
                for pass_count in &passes {
                    cell_index += 1;
                    let cell = GridCell {
                        impairment,
                        tag: format!("g{cell_index}"),
                        rate: *rate,
                        passes: *pass_count,
                    };
                    print!(
                        "grid: {} {profile_name}/{}pps/{}p … ",
                        shape.name, rate, pass_count
                    );
                    match grid_cell(&shape, &cell, cycles, &name, &mut records) {
                        Ok(()) => println!("ok"),
                        Err(err) => {
                            failures += 1;
                            println!("FAILED: {err}");
                        }
                    }
                }
            }
        }
    }
    let markdown = grid_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!(
        "grid: {} record(s), {} failure(s) — {} + .md",
        records.len(),
        failures,
        path.display()
    );
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{failures} grid cell(s) failed (see above)"))
    }
}

/// The configuration of one grid cell.
struct GridCell {
    impairment: ImpairSpec,
    tag: String,
    rate: u32,
    passes: u8,
}

/// One grid cell: lab, cycles, records appended to `records`.
fn grid_cell(
    shape: &Shape,
    cell: &GridCell,
    cycles: u32,
    experiment: &str,
    records: &mut Vec<RunRecord>,
) -> Result<(), String> {
    let spec = shape.lab_spec(cell.tag.clone(), cell.impairment)?;
    let mut lab = Lab::build(&spec)?;
    let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip);

    let mut cumulative: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut rx_seen = 0usize;
    let mut drops_seen = 0usize;
    for cycle in 1..=cycles {
        let facts = run_scan(&scanner, cell.passes, cell.rate, DEFAULT_LISTEN_WINDOW);
        let log = lab.rxlog();
        let sweep_ms = span_since(&log, rx_seen, &lab.our_mac, cell.rate);
        let drops = log.drops.saturating_sub(drops_seen) as u64;
        rx_seen = log.rx_total;
        drops_seen = log.drops;

        let this_cycle: BTreeSet<Ipv4Addr> = facts.observations.iter().map(|o| o.ip).collect();
        let before = cumulative.len();
        for ip in &this_cycle {
            cumulative.insert(*ip);
        }
        let hits = cumulative.intersection(&known).count();
        let extras = cumulative.difference(&known).count();
        let recall = hits as f64 / known.len().max(1) as f64 * 100.0;
        records.push(RunRecord {
            experiment: experiment.to_owned(),
            scenario: shape.name.to_owned(),
            variant: cell.impairment.label().to_owned()
                + &format!("/{}pps/{}p", cell.rate, cell.passes),
            cycle,
            seed: cell.impairment.seed,
            date: now_utc(),
            network_type: "netns synthetic (veth pair, user namespaces)",
            scope_size: lab.scope.host_count(),
            mode: "active",
            transport: "LinuxArpTransport (pnet_datalink 0.35.0, interim per ADR-009)".to_owned(),
            rate_pps: cell.rate,
            passes: cell.passes,
            sender_ip_variant: "interface IP",
            known_devices: known.len(),
            discovered_this_cycle: cumulative.len() - before,
            discovered_cumulative: cumulative.len(),
            recall_cumulative_pct: (recall * 100.0).round() / 100.0,
            extras,
            time_to_first_ms: facts.time_to_first_ms,
            sweep_duration_ms: sweep_ms,
            packets_sent: facts.counters.requests_sent,
            send_errors: facts.counters.send_errors_transient + facts.counters.send_errors_fatal,
            replies_accepted: facts.counters.replies_accepted,
            duplicates: facts.counters.duplicates,
            cap_dropped: facts.counters.cap_dropped,
            rejected_by_reason: rejection_tallies(&facts.counters),
            outcome: facts.outcome.to_string(),
            scan_elapsed_ms: facts.elapsed_ms,
            cpu_ms: facts.cpu_ms,
            responder_drops: drops,
            impairment_mechanism: "helper responder",
            notes: shape.note.to_owned(),
            ..RunRecord::default()
        });
    }
    lab.teardown();
    Ok(())
}

/// The responder-observed sweep span of the requests that arrived after
/// `seen` RX records (the per-cycle slice of the log).
fn span_since(log: &RxSummary, seen: usize, our_mac: &MacAddr, rate: u32) -> Option<u64> {
    let slice: Vec<u64> = log
        .requests
        .iter()
        .skip(seen.min(log.requests.len()))
        .filter(|request| {
            request
                .src
                .as_deref()
                .and_then(|src| src.parse::<MacAddr>().ok())
                .is_some_and(|src| src == *our_mac)
        })
        .map(|request| request.t)
        .collect();
    let first = slice.first()?;
    let last = slice.last()?;
    let interval = 1000 / u64::from(rate.max(1));
    Some(last - first + interval)
}

/// The Appendix D report table (per scenario), from the grid records.
fn grid_markdown(records: &[RunRecord]) -> String {
    let mut out = String::from(
        "# osza-netmon T-105 grid measurement\n\n\
         Generated by `poc_measure grid`; cumulative recall over each cell's cycles\n\
         against the known-device count. `Time to first` and `Sweep time` are the\n\
         cycle-1 values (per-cycle values in the JSON).\n",
    );
    let mut scenarios: Vec<&str> = Vec::new();
    for record in records {
        if !scenarios.contains(&record.scenario.as_str()) {
            scenarios.push(record.scenario.as_str());
        }
    }
    for scenario in scenarios {
        let cells: Vec<&RunRecord> = records
            .iter()
            .filter(|record| record.scenario == scenario && record.cycle == 1)
            .collect();
        let Some(first) = cells.first() else {
            continue;
        };
        out.push_str(&format!(
            "\n## {} — known devices: {}, scope size: {}\n\n{}\n\n",
            scenario, first.known_devices, first.scope_size, first.notes
        ));
        out.push_str("| Variant | Recall cycle 1 | Recall last | Extras | Time to first | Sweep time | Packets | Notes |\n");
        out.push_str("|---|---|---|---|---|---|---|---|\n");
        let max_cycle = records
            .iter()
            .filter(|record| record.scenario == scenario)
            .map(|record| record.cycle)
            .max()
            .unwrap_or(1);
        for record in cells {
            let last = records
                .iter()
                .find(|other| {
                    other.scenario == record.scenario
                        && other.variant == record.variant
                        && other.cycle == max_cycle
                })
                .unwrap_or(record);
            out.push_str(&format!(
                "| {} | {:.1}% | {:.1}% | {} | {} | {} | {} | seed {} |\n",
                record.variant,
                record.recall_cumulative_pct,
                last.recall_cumulative_pct,
                record.extras,
                record
                    .time_to_first_ms
                    .map(|v| format!("{v} ms"))
                    .unwrap_or_else(|| "—".to_owned()),
                record
                    .sweep_duration_ms
                    .map(|v| format!("{v} ms"))
                    .unwrap_or_else(|| "—".to_owned()),
                record.packets_sent,
                record.seed,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Experiment: sender-ip (interface IP vs 0.0.0.0)
// ---------------------------------------------------------------------------

/// `sender-ip` — the same cell under both sender variants, plus what
/// each variant did to the device-side kernel neighbor table.
fn cmd_sender_ip(args: &[String]) -> Result<(), String> {
    let scenarios = match list_of(args, "scenarios", &|s| {
        shape_by_name(s).map(|_| s.to_owned())
    }) {
        Some(list) => list?,
        None => vec!["s1".to_owned(), "s2".to_owned()],
    };
    let profiles = match list_of(args, "profiles", &|s| profile_for(s).map(|_| s.to_owned())) {
        Some(list) => list?,
        None => vec!["p0".to_owned(), "p3".to_owned()],
    };
    let cycles: u32 = value_of(args, "cycles")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let name = value_of(args, "name").unwrap_or_else(|| "sender-ip".to_owned());

    let mut records: Vec<RunRecord> = Vec::new();
    let mut cell_index = 0usize;
    for scenario_name in &scenarios {
        let shape = shape_by_name(scenario_name)?;
        for profile_name in &profiles {
            let impairment = profile_for(profile_name)?;
            for variant in ["iface", "zero"] {
                cell_index += 1;
                let tag = format!("s{cell_index}");
                let sender_ip_variant = if variant == "iface" {
                    "interface IP"
                } else {
                    "0.0.0.0 (RFC 5227)"
                };
                print!("sender-ip: {} {}/{} … ", shape.name, profile_name, variant);
                let spec = shape.lab_spec(tag, impairment)?;
                let mut lab = Lab::build(&spec)?;
                let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
                let socket =
                    open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
                let transport = LinuxArpTransport::new(socket);
                let mut scanner =
                    ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip);
                if variant == "zero" {
                    scanner = scanner.with_probe_sender_ip(Ipv4Addr::UNSPECIFIED);
                }

                let mut cumulative: BTreeSet<Ipv4Addr> = BTreeSet::new();
                for cycle in 1..=cycles {
                    let facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
                    let this_cycle: BTreeSet<Ipv4Addr> =
                        facts.observations.iter().map(|o| o.ip).collect();
                    let before = cumulative.len();
                    for ip in &this_cycle {
                        cumulative.insert(*ip);
                    }
                    let hits = cumulative.intersection(&known).count();
                    let extras = cumulative.difference(&known).count();
                    let recall = hits as f64 / known.len().max(1) as f64 * 100.0;
                    records.push(RunRecord {
                        experiment: name.clone(),
                        scenario: shape.name.to_owned(),
                        variant: format!("{}/{variant}", impairment.label()),
                        cycle,
                        seed: impairment.seed,
                        date: now_utc(),
                        network_type: "netns synthetic (veth pair, user namespaces)",
                        scope_size: lab.scope.host_count(),
                        mode: "active",
                        transport: "LinuxArpTransport (pnet_datalink 0.35.0, interim per ADR-009)"
                            .to_owned(),
                        rate_pps: 100,
                        passes: 2,
                        sender_ip_variant,
                        known_devices: known.len(),
                        discovered_this_cycle: cumulative.len() - before,
                        discovered_cumulative: cumulative.len(),
                        recall_cumulative_pct: (recall * 100.0).round() / 100.0,
                        extras,
                        time_to_first_ms: facts.time_to_first_ms,
                        sweep_duration_ms: None,
                        packets_sent: facts.counters.requests_sent,
                        send_errors: facts.counters.send_errors_transient
                            + facts.counters.send_errors_fatal,
                        replies_accepted: facts.counters.replies_accepted,
                        duplicates: facts.counters.duplicates,
                        cap_dropped: facts.counters.cap_dropped,
                        rejected_by_reason: rejection_tallies(&facts.counters),
                        outcome: facts.outcome.to_string(),
                        scan_elapsed_ms: facts.elapsed_ms,
                        cpu_ms: facts.cpu_ms,
                        responder_drops: 0,
                        impairment_mechanism: "helper responder",
                        notes: if cycle == cycles {
                            // After the last cycle: what our probes did to
                            // the device-side kernel neighbor table.
                            let rows = lab.device_arp_rows();
                            let entries = rows.lines().count().saturating_sub(1);
                            let mentions_us = rows.contains(&lab.our_ip.to_string());
                            format!(
                                "{}; device-side /proc/net/arp rows after scan: {entries}, \
                                 mentions our address: {mentions_us}",
                                shape.note
                            )
                        } else {
                            shape.note.to_owned()
                        },
                        ..RunRecord::default()
                    });
                }
                lab.teardown();
                println!("ok");
            }
        }
    }
    let markdown = grid_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!(
        "sender-ip: {} record(s) — {}",
        records.len(),
        path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Experiment: unicast refresh (ADR-011)
// ---------------------------------------------------------------------------

/// `unicast` — four phases over two labs:
///
/// * U1 cold unicast refresh (no prior sweep) — do kernel and helper
///   responders answer unicast requests at all?
/// * U2 broadcast sweep (the discovery baseline) then U3 warm unicast
///   refresh of exactly the discovered set — the periodic-refresh cost
///   model (N packets instead of a full /24 sweep).
/// * U4 the rotation case: a rebuilt lab with the same IPs behind new
///   MACs; refreshing the *stale* known set must find nothing (the
///   frames die at the old MACs), while U5's broadcast sweep recovers
///   every device with its new MAC — the data behind ADR-011's
///   unicast-refresh verdict.
fn cmd_unicast(args: &[String]) -> Result<(), String> {
    let rate: u32 = value_of(args, "rate")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RATE_PPS);
    let name = value_of(args, "name").unwrap_or_else(|| "unicast".to_owned());
    let mut records: Vec<RunRecord> = Vec::new();

    // Lab A: the S1 shape under P0, with a pinned device-side MAC so
    // the kernel half's link address is known before any discovery.
    let shape = Shape::s1()?;
    let peer_mac_a: MacAddr = "02:00:00:00:66:01"
        .parse()
        .map_err(|err| format!("bad pinned peer MAC: {err}"))?;
    let mut spec = shape.lab_spec("u1".to_owned(), ImpairSpec::p0(MEASURE_BASE))?;
    spec.peer_mac = Some(peer_mac_a);
    let mut lab = Lab::build(&spec)?;
    let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let device_mac = lab
        .device_mac
        .ok_or_else(|| "the unicast lab must pin the device-side MAC".to_owned())?;
    let mut all_pairs: Vec<(Ipv4Addr, MacAddr)> = shape
        .kernel_addrs
        .iter()
        .map(|ip| (*ip, device_mac))
        .collect();
    all_pairs.extend(shape.answers.iter().map(|a| (a.ip, a.mac)));

    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    let transport: Arc<dyn ArpTransport> = Arc::new(LinuxArpTransport::new(socket));

    // U1: cold unicast refresh of the (true) known set.
    let u1 = unicast_refresh(
        &transport,
        lab.scope,
        lab.our_mac,
        lab.our_ip,
        &all_pairs,
        rate,
        DEFAULT_LISTEN_WINDOW,
    );
    let log = lab.rxlog();
    // The T-106 log's `dst` field is a validating `MacAddr`, so a
    // broadcast destination is never logged (`None`); a present `dst`
    // marks exactly the unicast-delivered requests.
    let unicast_seen = log
        .requests_from(&lab.our_mac)
        .iter()
        .filter(|r| r.dst.is_some())
        .count();
    records.push(refresh_record(&name, &shape, "U1 cold unicast refresh", 1, rate, &u1, known.len(), format!(
        "unicast requests observed at responder: {unicast_seen}; kernel half answered: {}, helper half answered: {}",
        u1.replies.iter().filter(|(ip, _, _)| shape.kernel_addrs.contains(ip)).count(),
        u1.replies.iter().filter(|(ip, _, _)| !shape.kernel_addrs.contains(ip)).count(),
    )));

    // U2: broadcast discovery sweep (the baseline).
    let scanner = ArpScanner::new(make_transport(&lab)?, lab.scope, lab.our_mac, lab.our_ip);
    let u2 = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let discovered: Vec<(Ipv4Addr, MacAddr)> = u2
        .observations
        .iter()
        .map(|observation| (observation.ip, observation.mac))
        .collect();
    records.push(scan_record(&ScanPhase {
        experiment: &name,
        shape: &shape,
        variant: "U2 broadcast sweep",
        cycle: 2,
        facts: &u2,
        known: &known,
        discovered: &discovered,
        notes: "the discovery baseline before the warm refresh",
    }));

    // U3: warm unicast refresh of exactly the discovered set — on a
    // **fresh** socket: the U1 transport sat unread while U2 swept, and
    // an `ETH_P_ALL` socket accumulates every frame of that sweep in
    // its receive queue (itself a measured cost of the interim
    // transport); a periodic refresher opens its socket per phase.
    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    let transport: Arc<dyn ArpTransport> = Arc::new(LinuxArpTransport::new(socket));
    let u3 = unicast_refresh(
        &transport,
        lab.scope,
        lab.our_mac,
        lab.our_ip,
        &discovered,
        rate,
        DEFAULT_LISTEN_WINDOW,
    );
    records.push(refresh_record(
        &name,
        &shape,
        "U3 warm unicast refresh",
        3,
        rate,
        &u3,
        known.len(),
        format!(
            "packets for the same coverage: {} unicast vs {} broadcast (U2)",
            u3.sent, u2.counters.requests_sent
        ),
    ));
    lab.teardown();

    // Lab B: the same IPs behind rotated MACs (the rotation case) —
    // both halves rotate: the helper answer table and the pinned
    // device-side veth address.
    let peer_mac_b: MacAddr = "02:00:00:00:66:02"
        .parse()
        .map_err(|err| format!("bad rotated peer MAC: {err}"))?;
    let mut rotated_answers = shape.answers.clone();
    for answer in &mut rotated_answers {
        let octets = answer.mac.octets();
        let rotated = [octets[0], octets[1], octets[2], octets[3], 0x02, octets[5]];
        answer.mac = MacAddr::from_octets(rotated).map_err(|err| format!("rotating MAC: {err}"))?;
    }
    let mut spec_b = LabSpec {
        tag: "u2".to_owned(),
        subnet: parse_cidr(shape.subnet)?,
        kernel_addrs: shape.kernel_addrs.clone(),
        answers: rotated_answers,
        impairment: ImpairSpec::p0(MEASURE_BASE),
        peer_mac: Some(peer_mac_b),
        background: None,
        pre_traffic: None,
    };
    spec_b.tag = "u2".to_owned();
    let mut lab_b = Lab::build(&spec_b)?;
    let socket_b = open_raw_socket(&lab_b.host_if).map_err(|err| format!("socket: {err}"))?;
    let transport_b: Arc<dyn ArpTransport> = Arc::new(LinuxArpTransport::new(socket_b));

    // U4: refresh the stale (pre-rotation) set — the kernel half must
    // stay silent (the kernel drops requests addressed to a MAC that is
    // no longer its own); the helper half answers anyway (a raw socket
    // on veth still sees those frames — a harness asymmetry the report
    // documents: real NICs filter unicast in hardware).
    let u4 = unicast_refresh(
        &transport_b,
        lab_b.scope,
        lab_b.our_mac,
        lab_b.our_ip,
        &discovered,
        rate,
        DEFAULT_LISTEN_WINDOW,
    );
    records.push(refresh_record(
        &name,
        &shape,
        "U4 stale-MAC unicast refresh (rotation)",
        4,
        rate,
        &u4,
        known.len(),
        format!(
            "lab rebuilt with rotated MACs; kernel half answered: {} (drops requests \
             addressed to the stale MAC), helper half answered: {} (veth raw-socket \
             asymmetry — see the report)",
            u4.replies
                .iter()
                .filter(|(ip, _, _)| shape.kernel_addrs.contains(ip))
                .count(),
            u4.replies
                .iter()
                .filter(|(ip, _, _)| !shape.kernel_addrs.contains(ip))
                .count(),
        ),
    ));

    // U5: broadcast sweep recovers everything with the new MACs.
    let scanner_b = ArpScanner::new(
        make_transport(&lab_b)?,
        lab_b.scope,
        lab_b.our_mac,
        lab_b.our_ip,
    );
    let u5 = run_scan(&scanner_b, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let discovered_b: Vec<(Ipv4Addr, MacAddr)> = u5
        .observations
        .iter()
        .map(|observation| (observation.ip, observation.mac))
        .collect();
    records.push(scan_record(&ScanPhase {
        experiment: &name,
        shape: &shape,
        variant: "U5 broadcast sweep after rotation",
        cycle: 5,
        facts: &u5,
        known: &known,
        discovered: &discovered_b,
        notes: "recovery with the rotated MACs; compare U4: unicast refresh cannot see rotation",
    }));
    lab_b.teardown();

    let markdown = unicast_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!("unicast: {} record(s) — {}", records.len(), path.display());
    Ok(())
}

/// Opens a second socket + transport for the broadcast scanner (the
/// unicast phases hold the first one).
fn make_transport(lab: &Lab) -> Result<Box<dyn ArpTransport>, String> {
    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    Ok(Box::new(LinuxArpTransport::new(socket)))
}

/// A record for one unicast-refresh phase.
#[allow(clippy::too_many_arguments)]
fn refresh_record(
    experiment: &str,
    shape: &Shape,
    variant: &str,
    cycle: u32,
    rate: u32,
    facts: &RefreshFacts,
    known: usize,
    notes: String,
) -> RunRecord {
    RunRecord {
        experiment: experiment.to_owned(),
        scenario: shape.name.to_owned(),
        variant: variant.to_owned(),
        cycle,
        seed: MEASURE_BASE,
        date: now_utc(),
        network_type: "netns synthetic (veth pair, user namespaces)",
        scope_size: 254,
        mode: "active (unicast refresh)",
        transport: "LinuxArpTransport (pnet_datalink 0.35.0, interim per ADR-009)".to_owned(),
        rate_pps: rate,
        passes: 1,
        sender_ip_variant: "interface IP",
        known_devices: known,
        discovered_this_cycle: facts.replies.len(),
        discovered_cumulative: facts.replies.len(),
        recall_cumulative_pct: facts.replies.len() as f64 / known.max(1) as f64 * 100.0,
        extras: 0,
        time_to_first_ms: facts.replies.first().map(|(_, _, at)| *at),
        sweep_duration_ms: None,
        packets_sent: facts.sent,
        send_errors: facts.send_errors,
        replies_accepted: facts.replies.len() as u64,
        duplicates: 0,
        cap_dropped: 0,
        rejected_by_reason: Vec::new(),
        outcome: "refresh".to_owned(),
        scan_elapsed_ms: facts.elapsed_ms,
        cpu_ms: facts.cpu_ms,
        responder_drops: 0,
        impairment_mechanism: "helper responder",
        notes: format!("{notes}; rejected replies: {}", facts.rejected),
        ..RunRecord::default()
    }
}

/// The inputs of one broadcast scan phase record.
struct ScanPhase<'a> {
    experiment: &'a str,
    shape: &'a Shape,
    variant: &'a str,
    cycle: u32,
    facts: &'a ScanFacts,
    known: &'a BTreeSet<Ipv4Addr>,
    discovered: &'a [(Ipv4Addr, MacAddr)],
    notes: &'a str,
}

/// A record for one broadcast scan phase of the unicast experiment.
fn scan_record(phase: &ScanPhase<'_>) -> RunRecord {
    let discovered_ips: BTreeSet<Ipv4Addr> = phase.discovered.iter().map(|(ip, _)| *ip).collect();
    let hits = discovered_ips.intersection(phase.known).count();
    RunRecord {
        experiment: phase.experiment.to_owned(),
        scenario: phase.shape.name.to_owned(),
        variant: phase.variant.to_owned(),
        cycle: phase.cycle,
        seed: MEASURE_BASE,
        date: now_utc(),
        network_type: "netns synthetic (veth pair, user namespaces)",
        scope_size: 254,
        mode: "active",
        transport: "LinuxArpTransport (pnet_datalink 0.35.0, interim per ADR-009)".to_owned(),
        rate_pps: DEFAULT_RATE_PPS,
        passes: 2,
        sender_ip_variant: "interface IP",
        known_devices: phase.known.len(),
        discovered_this_cycle: phase.discovered.len(),
        discovered_cumulative: phase.discovered.len(),
        recall_cumulative_pct: hits as f64 / phase.known.len().max(1) as f64 * 100.0,
        extras: discovered_ips.difference(phase.known).count(),
        time_to_first_ms: phase.facts.time_to_first_ms,
        sweep_duration_ms: None,
        packets_sent: phase.facts.counters.requests_sent,
        send_errors: phase.facts.counters.send_errors_transient
            + phase.facts.counters.send_errors_fatal,
        replies_accepted: phase.facts.counters.replies_accepted,
        duplicates: phase.facts.counters.duplicates,
        cap_dropped: phase.facts.counters.cap_dropped,
        rejected_by_reason: rejection_tallies(&phase.facts.counters),
        outcome: phase.facts.outcome.to_string(),
        scan_elapsed_ms: phase.facts.elapsed_ms,
        cpu_ms: phase.facts.cpu_ms,
        responder_drops: 0,
        impairment_mechanism: "helper responder",
        notes: phase.notes.to_owned(),
        ..RunRecord::default()
    }
}

/// The unicast experiment's table.
fn unicast_markdown(records: &[RunRecord]) -> String {
    let mut out = String::from(
        "# osza-netmon T-105 unicast-refresh experiment\n\n\
         Phases U1–U5 (see the module docs of `cmd_unicast`): cold refresh,\n\
         broadcast baseline, warm refresh, stale-MAC rotation, recovery sweep.\n\n\
         | Phase | Packets | Accepted | Recall | Elapsed | Notes |\n\
         |---|---|---|---|---|---|\n",
    );
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1}% | {} ms | {} |\n",
            record.variant,
            record.packets_sent,
            record.replies_accepted,
            record.recall_cumulative_pct,
            record.scan_elapsed_ms,
            record.notes
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Experiment: late (pass-2 snapshot semantics, T-104 review F-6)
// ---------------------------------------------------------------------------

/// `late` — a fixed reply delay longer than the pass gap, so pass-1
/// answers land after the pass-2 non-responder snapshot: those
/// addresses are re-probed exactly once and their late replies still
/// count (solicited in pass 1). The responder's per-address request
/// counts are the direct evidence.
fn cmd_late(args: &[String]) -> Result<(), String> {
    let delay_ms: u64 = value_of(args, "delay-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2500);
    let passes: u8 = value_of(args, "passes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let name = value_of(args, "name").unwrap_or_else(|| "late".to_owned());

    let shape = Shape::s1()?;
    let impairment = ImpairSpec::fixed_delay(MEASURE_BASE + 200, delay_ms);
    let spec = shape.lab_spec("l1".to_owned(), impairment)?;
    let mut lab = Lab::build(&spec)?;
    let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    let scanner = ArpScanner::new(
        Box::new(LinuxArpTransport::new(socket)),
        lab.scope,
        lab.our_mac,
        lab.our_ip,
    );
    let facts = run_scan(&scanner, passes, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let log = lab.rxlog();
    let per_target = log.requests_per_target();
    let re_probed = per_target.values().filter(|count| **count >= 2).count();
    let probed_once = per_target.values().filter(|count| **count == 1).count();
    lab.teardown();

    let discovered_pairs: Vec<(Ipv4Addr, MacAddr)> =
        facts.observations.iter().map(|o| (o.ip, o.mac)).collect();
    let discovered: BTreeSet<Ipv4Addr> = facts.observations.iter().map(|o| o.ip).collect();
    let hits = discovered.intersection(&known).count();
    let mut record = scan_record(&ScanPhase {
        experiment: &name,
        shape: &shape,
        variant: &format!("fixed-{delay_ms}ms/{passes}p"),
        cycle: 1,
        facts: &facts,
        known: &known,
        discovered: &discovered_pairs,
        notes: "pass-2 snapshot semantics under a fixed long delay",
    });
    record.notes = format!(
        "responder request counts: {re_probed} addresses probed twice (late answers \
         re-probed once per the pass-start snapshot), {probed_once} probed once; \
         TX answers: {}; accepted: {}",
        log.answers, facts.counters.replies_accepted
    );
    let records = vec![record];
    let _ = hits;
    let markdown = unicast_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!("late: {} record(s) — {}", records.len(), path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Experiment: transport (ETH_P_ALL + software filter cost, and the
// ETH_P_ARP-binding alternative measured by a kernel-level witness)
// ---------------------------------------------------------------------------

/// `transport` — the same S1 scan under increasing non-ARP background
/// rates, with the production transport wrapped in a counter, plus a
/// Python `AF_PACKET`/`ETH_P_ARP` witness socket counting what a
/// kernel EtherType binding would have delivered.
fn cmd_transport(args: &[String]) -> Result<(), String> {
    let rates = match list_of(args, "rates", &parse_u32) {
        Some(list) => list?,
        None => vec![0, 50, 200, 800],
    };
    let duration_s: u64 = value_of(args, "duration")
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    let name = value_of(args, "name").unwrap_or_else(|| "transport".to_owned());
    let shape = Shape::s1()?;
    let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let mut records: Vec<RunRecord> = Vec::new();

    for (index, bg_rate) in rates.iter().enumerate() {
        let tag = format!("t{index}");
        print!("transport: bg {bg_rate} pps … ");
        let mut spec = shape.lab_spec(tag, ImpairSpec::p0(MEASURE_BASE))?;
        if *bg_rate > 0 {
            spec.background = Some((*bg_rate, duration_s));
        }
        let mut lab = Lab::build(&spec)?;

        // The witness (kernel-level ETH_P_ARP delivery) runs for the
        // same window as the scan; its output is read when it exits.
        let witness_path = lab.artifacts.join("witness.py");
        let witness_log = lab.artifacts.join("witness.log");
        fs::write(&witness_path, ARP_WITNESS_PY)
            .map_err(|err| format!("writing witness.py: {err}"))?;
        let witness = Command::new("python3")
            .arg(&witness_path)
            .arg(&lab.host_if)
            .arg(duration_s.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| format!("spawning the witness: {err}"))?;
        // Let the witness bind before the first probe leaves (Python
        // startup is ~100 ms; the scan's first replies arrive within
        // tens of milliseconds).
        thread::sleep(Duration::from_millis(400));

        // The counted production transport.
        let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
        let counts = Arc::new(TransportCounts::default());
        let counted = CountingTransport {
            inner: LinuxArpTransport::new(socket),
            counts: Arc::clone(&counts),
        };
        let scanner = ArpScanner::new(Box::new(counted), lab.scope, lab.our_mac, lab.our_ip);
        let facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
        let (frames_total, non_arp, arp) = counts.snapshot();

        let witness_out = witness
            .wait_with_output()
            .map_err(|err| format!("waiting for the witness: {err}"))?;
        let _ = fs::write(&witness_log, &witness_out.stdout);
        let (witness_in, witness_outgoing) =
            parse_witness(&String::from_utf8_lossy(&witness_out.stdout));

        let discovered: BTreeSet<Ipv4Addr> = facts.observations.iter().map(|o| o.ip).collect();
        let hits = discovered.intersection(&known).count();
        let extras = discovered.difference(&known).count();
        records.push(RunRecord {
            experiment: name.clone(),
            scenario: shape.name.to_owned(),
            variant: format!("bg-{bg_rate}pps"),
            cycle: 1,
            seed: MEASURE_BASE,
            date: now_utc(),
            network_type: "netns synthetic (veth pair, user namespaces)",
            scope_size: lab.scope.host_count(),
            mode: "active",
            transport: "LinuxArpTransport + counting wrapper (pnet_datalink 0.35.0, \
                        ETH_P_ALL + software filter)"
                .to_owned(),
            rate_pps: DEFAULT_RATE_PPS,
            passes: 2,
            sender_ip_variant: "interface IP",
            known_devices: known.len(),
            discovered_this_cycle: discovered.len(),
            discovered_cumulative: discovered.len(),
            recall_cumulative_pct: hits as f64 / known.len().max(1) as f64 * 100.0,
            extras,
            time_to_first_ms: facts.time_to_first_ms,
            sweep_duration_ms: None,
            packets_sent: facts.counters.requests_sent,
            send_errors: facts.counters.send_errors_transient + facts.counters.send_errors_fatal,
            replies_accepted: facts.counters.replies_accepted,
            duplicates: facts.counters.duplicates,
            cap_dropped: facts.counters.cap_dropped,
            rejected_by_reason: rejection_tallies(&facts.counters),
            outcome: facts.outcome.to_string(),
            scan_elapsed_ms: facts.elapsed_ms,
            cpu_ms: facts.cpu_ms,
            responder_drops: 0,
            impairment_mechanism: "helper responder (background: raw EtherType 0x1234 frames)",
            transport_frames_total: Some(frames_total),
            transport_non_arp: Some(non_arp),
            transport_arp: Some(arp),
            witness_arp_in: witness_in,
            witness_outgoing,
            notes: format!(
                "background {bg_rate} pps for {duration_s}s; witness = AF_PACKET/ETH_P_ARP \
                 socket (kernel-filtered delivery)"
            ),
        });
        lab.teardown();
        println!("ok (non-ARP seen {non_arp}, cpu {:?} ms)", facts.cpu_ms);
    }

    let markdown = transport_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!(
        "transport: {} record(s) — {}",
        records.len(),
        path.display()
    );
    Ok(())
}

/// Parses the witness's `WITNESS total=… in=… outgoing=…` line.
fn parse_witness(text: &str) -> (Option<u64>, Option<u64>) {
    let inbound = number(text, "in=");
    let outgoing = number(text, "outgoing=");
    (inbound, outgoing)
}

/// The transport experiment's table.
fn transport_markdown(records: &[RunRecord]) -> String {
    let mut out = String::from(
        "# osza-netmon T-105 transport cost experiment\n\n\
         The S1 scan (2 passes, 100 pps) under controlled non-ARP background rates.\n\
         `non-ARP seen` counts the frames the production `ETH_P_ALL` socket delivered\n\
         to userspace and the software EtherType filter dropped; `witness in` counts\n\
         the ARP frames an `AF_PACKET`/`ETH_P_ARP` socket received over the same\n\
         window (what a kernel-level binding would deliver).\n\n\
         | Background | Non-ARP seen | ARP seen | Witness ARP in | Witness out | CPU ms | Elapsed ms | Accepted |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for record in records {
        let cell = |value: Option<u64>| {
            value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".to_owned())
        };
        out.push_str(&format!(
            "| {} pps | {} | {} | {} | {} | {} | {} | {} |\n",
            record
                .variant
                .trim_start_matches("bg-")
                .trim_end_matches("pps"),
            cell(record.transport_non_arp),
            cell(record.transport_arp),
            cell(record.witness_arp_in),
            cell(record.witness_outgoing),
            cell(record.cpu_ms),
            record.scan_elapsed_ms,
            record.replies_accepted,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Experiment: neighbor (/proc/net/arp vs netlink RTM_GETNEIGH)
// ---------------------------------------------------------------------------

/// One timeline sample of both neighbor sources.
struct NeighborSample {
    at_s: u64,
    proc_entries: Vec<(Ipv4Addr, String)>,
    netlink_entries: Vec<(Ipv4Addr, String)>,
}

/// `neighbor` — a lab whose device side runs real IP traffic to the
/// host (bound sources, one-way UDP), sampled over time through both
/// sources: the production `/proc/net/arp` reader and netlink
/// `RTM_GETNEIGH` (via `ip neigh`, the same kernel source a Rust
/// netlink client would read). Also: what our own ARP sweeps do and do
/// not populate, and the read costs.
fn cmd_neighbor(args: &[String]) -> Result<(), String> {
    let devices: u8 = value_of(args, "devices")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let traffic_s: u64 = value_of(args, "traffic-duration")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let timeline: Vec<u64> = match list_of(args, "timeline", &parse_u64) {
        Some(list) => list?,
        None => vec![2, traffic_s + 2, 45, 75],
    };
    let name = value_of(args, "name").unwrap_or_else(|| "neighbor".to_owned());

    let kernel_addrs: Vec<Ipv4Addr> = (2u8..2 + devices)
        .map(|host| Ipv4Addr::new(192, 0, 2, u32::from(host) as u8))
        .collect();
    let spec = LabSpec {
        tag: "n1".to_owned(),
        subnet: parse_cidr("192.0.2.0/24")?,
        kernel_addrs: kernel_addrs.clone(),
        answers: Vec::new(), // the responder only logs
        impairment: ImpairSpec::p0(MEASURE_BASE),
        peer_mac: None,
        background: None,
        pre_traffic: Some(PreTraffic {
            srcs: kernel_addrs.clone(),
            host: Ipv4Addr::new(192, 0, 2, 1),
            duration_s: traffic_s,
            interval_ms: 1000,
        }),
    };
    let mut lab = Lab::build(&spec)?;

    // Drain the device's UDP so the host sends nothing back.
    let drain = UdpSocket::bind(("0.0.0.0", NEIGHBOR_UDP_PORT))
        .map_err(|err| format!("binding the drain socket: {err}"))?;
    drain
        .set_nonblocking(true)
        .map_err(|err| format!("drain socket: {err}"))?;
    let drain_stop = Arc::new(AtomicBool::new(false));
    let drain_flag = Arc::clone(&drain_stop);
    let drainer = thread::spawn(move || {
        let mut buffer = [0u8; 64];
        while !drain_flag.load(Ordering::Acquire) {
            let _ = drain.recv_from(&mut buffer);
            thread::sleep(Duration::from_millis(20));
        }
    });

    let started = Instant::now();
    let mut samples: Vec<NeighborSample> = Vec::new();
    for at_s in &timeline {
        let wait = Duration::from_secs(*at_s).saturating_sub(started.elapsed());
        thread::sleep(wait);
        samples.push(NeighborSample {
            at_s: *at_s,
            proc_entries: read_proc_neighbors(&lab.scope, &lab.host_if),
            netlink_entries: read_netlink_neighbors(&lab.host_if),
        });
    }
    drain_stop.store(true, Ordering::Release);
    let _ = drainer.join();

    // What our own sweep does to the table: scan, then re-sample.
    let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
    let scanner = ArpScanner::new(
        Box::new(LinuxArpTransport::new(socket)),
        lab.scope,
        lab.our_mac,
        lab.our_ip,
    );
    let after_scan_facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let after_proc = read_proc_neighbors(&lab.scope, &lab.host_if);
    let after_netlink = read_netlink_neighbors(&lab.host_if);

    // Read costs: the production reader vs `ip neigh` spawns (an upper
    // bound for a netlink client; the syscall itself is cheaper).
    let proc_cost = time_reads(200, || {
        let _ = read_proc_neighbors(&lab.scope, &lab.host_if);
    });
    let ip_cost = time_reads(20, || {
        let _ = read_netlink_neighbors(&lab.host_if);
    });
    lab.teardown();

    // Records: one per timeline sample + the post-scan sample.
    let mut records: Vec<RunRecord> = Vec::new();
    for sample in &samples {
        records.push(neighbor_record(
            &name,
            &format!("t={}s (traffic {}s)", sample.at_s, traffic_s),
            sample,
            "",
        ));
    }
    let post = NeighborSample {
        at_s: started.elapsed().as_secs(),
        proc_entries: after_proc,
        netlink_entries: after_netlink,
    };
    let mut post_record = neighbor_record(
        &name,
        "after active scan (2 passes)",
        &post,
        &format!(
            "scan accepted {} devices; proc read cost ≈ {:.0} µs, `ip neigh` spawn ≈ {:.1} ms",
            after_scan_facts.counters.replies_accepted,
            proc_cost * 1_000_000.0,
            ip_cost * 1000.0
        ),
    );
    post_record.packets_sent = after_scan_facts.counters.requests_sent;
    post_record.replies_accepted = after_scan_facts.counters.replies_accepted;
    post_record.scan_elapsed_ms = after_scan_facts.elapsed_ms;
    post_record.cpu_ms = after_scan_facts.cpu_ms;
    records.push(post_record);

    let markdown = neighbor_markdown(&records, proc_cost, ip_cost);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!("neighbor: {} record(s) — {}", records.len(), path.display());
    Ok(())
}

/// Reads the in-scope neighbor entries through the **production**
/// source (T-102): `(ip, "flags 0x…")`.
fn read_proc_neighbors(scope: &Ipv4Net, iface: &str) -> Vec<(Ipv4Addr, String)> {
    match ProcNeighborTable::new().read_neighbors(scope, iface) {
        Ok(entries) => entries
            .iter()
            .map(|entry| (entry.ip(), format!("{}", entry.mac())))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Reads the netlink `RTM_GETNEIGH` view via `ip neigh` (total parse):
/// `(ip, state)` for our interface.
fn read_netlink_neighbors(iface: &str) -> Vec<(Ipv4Addr, String)> {
    let output = Command::new("ip")
        .arg("neigh")
        .arg("show")
        .arg("dev")
        .arg(iface)
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(ip_text) = fields.next() else {
            continue;
        };
        let Ok(ip) = ip_text.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(state) = fields.last().map(str::to_owned) else {
            continue;
        };
        out.push((ip, state));
    }
    out
}

/// Times `rounds` executions of `body`, returning the mean seconds.
fn time_reads(rounds: u32, body: impl Fn()) -> f64 {
    let started = Instant::now();
    for _ in 0..rounds {
        body();
    }
    started.elapsed().as_secs_f64() / f64::from(rounds.max(1))
}

/// One neighbor-sample record.
fn neighbor_record(
    experiment: &str,
    variant: &str,
    sample: &NeighborSample,
    extra: &str,
) -> RunRecord {
    let proc_list = sample
        .proc_entries
        .iter()
        .map(|(ip, mac)| format!("{ip}→{mac}"))
        .collect::<Vec<_>>()
        .join(", ");
    let netlink_list = sample
        .netlink_entries
        .iter()
        .map(|(ip, state)| format!("{ip}={state}"))
        .collect::<Vec<_>>()
        .join(", ");
    RunRecord {
        experiment: experiment.to_owned(),
        scenario: "neighbor sources (5 kernel devices, one-way UDP traffic)".to_owned(),
        variant: variant.to_owned(),
        cycle: 1,
        seed: MEASURE_BASE,
        date: now_utc(),
        network_type: "netns synthetic (veth pair, user namespaces)",
        scope_size: 254,
        mode: "observation",
        transport: "n/a (neighbor-table read)".to_owned(),
        known_devices: 5,
        discovered_this_cycle: sample.proc_entries.len(),
        discovered_cumulative: sample.proc_entries.len(),
        recall_cumulative_pct: sample.proc_entries.len() as f64 * 20.0,
        notes: format!(
            "proc/net/arp ({}): [{}]; netlink RTM_GETNEIGH ({}): [{}] {}",
            sample.proc_entries.len(),
            proc_list,
            sample.netlink_entries.len(),
            netlink_list,
            extra
        ),
        ..RunRecord::default()
    }
}

/// The neighbor experiment's table.
fn neighbor_markdown(records: &[RunRecord], proc_cost_s: f64, ip_cost_s: f64) -> String {
    let mut out = String::from(
        "# osza-netmon T-105 neighbor-source experiment\n\n\
         Five kernel-answered devices send one-way UDP to the host for 10 s\n\
         (the only real IP traffic); both neighbor sources are sampled over\n\
         time, then once more after a full active ARP sweep.\n\n\
         | Sample | /proc/net/arp | netlink states |\n\
         |---|---|---|\n",
    );
    for record in records {
        out.push_str(&format!("| {} | see notes | see notes |\n", record.variant));
    }
    out.push_str(&format!(
        "\nRead costs (mean): production `/proc/net/arp` reader ≈ {:.0} µs; `ip neigh`\n\
         spawn ≈ {:.1} ms (an upper bound for a netlink client — the RTM_GETNEIGH\n\
         dump itself is a handful of syscalls, no process spawn).\n\n\
         Per-sample contents are in the JSON `notes` fields.\n",
        proc_cost_s * 1_000_000.0,
        ip_cost_s * 1000.0
    ));
    out
}

// ---------------------------------------------------------------------------
// Experiment: observe (the Owner-network stand-in)
// ---------------------------------------------------------------------------

/// `observe` — a client-isolated Wi-Fi stand-in: one answering
/// "gateway" (192.0.2.254), one infrastructure peer that talks to us
/// briefly (192.0.2.2, the neighbor-table path's yield), everything
/// else silent. The T-104 boundary binary `poc_discover` is driven in
/// both modes; the real Owner session is human-run per plan §13 and
/// uses the same commands (§ report runbook).
fn cmd_observe(args: &[String]) -> Result<(), String> {
    let name = value_of(args, "name").unwrap_or_else(|| "observe".to_owned());
    let gateway: MacAddr = "02:00:00:00:00:fe"
        .parse()
        .map_err(|err| format!("bad gateway MAC: {err}"))?;
    let spec = LabSpec {
        tag: "o1".to_owned(),
        subnet: parse_cidr("192.0.2.0/24")?,
        kernel_addrs: vec![Ipv4Addr::new(192, 0, 2, 2)],
        answers: vec![Answer {
            ip: Ipv4Addr::new(192, 0, 2, 254),
            mac: gateway,
        }],
        impairment: ImpairSpec::p0(MEASURE_BASE),
        peer_mac: None,
        background: None,
        pre_traffic: Some(PreTraffic {
            srcs: vec![Ipv4Addr::new(192, 0, 2, 2)],
            host: Ipv4Addr::new(192, 0, 2, 1),
            duration_s: 8,
            interval_ms: 500,
        }),
    };
    let mut lab = Lab::build(&spec)?;
    // Let the infrastructure chatter finish so the neighbor table has
    // its entries (the "recently talking peers" of a real network).
    thread::sleep(Duration::from_secs(10));

    let poc = poc_discover_binary()?;
    let mut records: Vec<RunRecord> = Vec::new();

    // Run A: privileged (active mode, honest near-zero visibility).
    let started = Instant::now();
    let output = Command::new(&poc)
        .arg(&lab.host_if)
        .output()
        .map_err(|err| format!("running poc_discover: {err}"))?;
    let elapsed = started.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = fs::write(lab.artifacts.join("observe-active.out"), &stdout);
    let _ = fs::write(lab.artifacts.join("observe-active.err"), &stderr);
    let combined = format!("{stdout}{stderr}");
    records.push(observe_record(
        &name,
        "A: active (privileged, as userns root)",
        &combined,
        output.status.code().unwrap_or(-1),
        elapsed,
    ));

    // Run B: read-only (no CAP_NET_RAW, via the drop-netraw-exec
    // driver — the S7(a) capability pattern).
    let me = std::env::current_exe().map_err(|err| format!("locating myself: {err}"))?;
    let started = Instant::now();
    let output = Command::new(&me)
        .arg("drop-netraw-exec")
        .arg("--")
        .arg(&poc)
        .arg(&lab.host_if)
        .output()
        .map_err(|err| format!("running the read-only observation: {err}"))?;
    let elapsed = started.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = fs::write(lab.artifacts.join("observe-readonly.out"), &stdout);
    let _ = fs::write(lab.artifacts.join("observe-readonly.err"), &stderr);
    let combined = format!("{stdout}{stderr}");
    records.push(observe_record(
        &name,
        "B: read-only (CAP_NET_RAW dropped before start)",
        &combined,
        output.status.code().unwrap_or(-1),
        elapsed,
    ));
    lab.teardown();

    let markdown = observe_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!("observe: {} record(s) — {}", records.len(), path.display());
    Ok(())
}

/// Parses `poc_discover`'s output into one record.
fn observe_record(
    experiment: &str,
    variant: &str,
    output: &str,
    exit_code: i32,
    elapsed_ms: u128,
) -> RunRecord {
    let mut neighbor_count: Option<u64> = None;
    let mut arp_observations = 0u64;
    let mut neighbor_observations = 0u64;
    let mut summary_lines: Vec<&str> = Vec::new();
    let mut read_only = false;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("neighbor table: ") {
            neighbor_count = rest
                .split_whitespace()
                .next()
                .and_then(|count| count.parse().ok());
        } else if line.ends_with("(arp reply)") {
            arp_observations += 1;
        } else if line.ends_with("(neighbor table)") {
            neighbor_observations += 1;
        } else if line.starts_with("summary: ") || line.starts_with("mode: ") {
            summary_lines.push(line);
        }
        if line.contains("read-only") {
            read_only = true;
        }
    }
    RunRecord {
        experiment: experiment.to_owned(),
        scenario: "isolated Wi-Fi stand-in (1 gateway, 1 infrastructure peer, 252 silent)"
            .to_owned(),
        variant: variant.to_owned(),
        cycle: 1,
        date: now_utc(),
        network_type: "netns synthetic (client-isolation shape)",
        scope_size: 254,
        mode: if read_only { "read-only" } else { "active" },
        known_devices: 2,
        discovered_this_cycle: usize::try_from(arp_observations + neighbor_observations)
            .unwrap_or(0),
        outcome: format!("exit {exit_code}"),
        scan_elapsed_ms: elapsed_ms,
        notes: format!(
            "neighbor table rows: {:?}; observations: {} arp + {} neighbor; {}",
            neighbor_count,
            arp_observations,
            neighbor_observations,
            summary_lines.join(" | ")
        ),
        ..RunRecord::default()
    }
}

/// The observe experiment's table.
fn observe_markdown(records: &[RunRecord]) -> String {
    let mut out = String::from(
        "# osza-netmon T-105 isolated-Wi-Fi stand-in observation\n\n\
         The Owner's client-isolated Wi-Fi, modeled in netns: the AP answers for\n\
         the gateway only; one infrastructure peer talks to us briefly (the\n\
         neighbor-table yield); 252 addresses stay silent. The T-104 `poc_discover`\n\
         boundary binary runs in both privilege modes; clean completion and the\n\
         honest limited-visibility output are the pass conditions (near-zero\n\
         visibility is expected, not a failure — plan §12.2 G-1).\n\n\
         | Run | Mode | Exit | Elapsed | Observations | Notes |\n\
         |---|---|---|---|---|---|\n",
    );
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {} ms | {} | {} |\n",
            record.variant,
            record.mode,
            record.outcome,
            record.scan_elapsed_ms,
            record.discovered_this_cycle,
            record.notes
        ));
    }
    out
}

/// Locates the T-104 `poc_discover` example binary (sibling of this
/// example; `OSZA_POC_DISCOVER_BIN` wins).
fn poc_discover_binary() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("OSZA_POC_DISCOVER_BIN")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .map(|dir| dir.join("poc_discover"));
    match sibling {
        Some(path) if path.exists() => Ok(path),
        _ => Err("poc_discover was not found next to this example; run \
             `cargo build --example poc_discover` or set OSZA_POC_DISCOVER_BIN"
            .to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Experiment: iface-flip (the interface down/up mid-scan failure case)
// ---------------------------------------------------------------------------

/// `iface-flip` — F1: the link goes down mid-scan (bounded failure,
/// honest outcome, no hang); F2: recovery scan with the link back up;
/// F3: the link already down at scan start.
fn cmd_iface_flip(args: &[String]) -> Result<(), String> {
    let name = value_of(args, "name").unwrap_or_else(|| "iface-flip".to_owned());
    let flip_after_ms: u64 = value_of(args, "flip-after-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let shape = Shape::s1()?;
    let known: BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let mut records: Vec<RunRecord> = Vec::new();

    // F1: down mid-scan.
    {
        let spec = shape.lab_spec("f1".to_owned(), ImpairSpec::p0(MEASURE_BASE))?;
        let mut lab = Lab::build(&spec)?;
        let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
        let scanner = ArpScanner::new(
            Box::new(LinuxArpTransport::new(socket)),
            lab.scope,
            lab.our_mac,
            lab.our_ip,
        );
        let flipper = spawn_flip(&lab.host_if, flip_after_ms, "down");
        let facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
        let _ = flipper.join();
        records.push(flip_record(
            &name,
            &shape,
            "F1 link down mid-scan",
            &facts,
            &known,
        ));
        // F2: link back up, recovery scan.
        run_ip(
            &["link", "set", &lab.host_if, "up"],
            "F2: bringing the link back up",
        )?;
        thread::sleep(Duration::from_millis(300));
        let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
        let scanner = ArpScanner::new(
            Box::new(LinuxArpTransport::new(socket)),
            lab.scope,
            lab.our_mac,
            lab.our_ip,
        );
        let facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
        records.push(flip_record(
            &name,
            &shape,
            "F2 recovery scan (link up again)",
            &facts,
            &known,
        ));
        lab.teardown();
    }

    // F3: down before the scan starts.
    {
        let spec = shape.lab_spec("f2".to_owned(), ImpairSpec::p0(MEASURE_BASE))?;
        let mut lab = Lab::build(&spec)?;
        run_ip(
            &["link", "set", &lab.host_if, "down"],
            "F3: taking the link down",
        )?;
        let socket = open_raw_socket(&lab.host_if).map_err(|err| format!("socket: {err}"))?;
        let scanner = ArpScanner::new(
            Box::new(LinuxArpTransport::new(socket)),
            lab.scope,
            lab.our_mac,
            lab.our_ip,
        );
        let facts = run_scan(&scanner, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
        records.push(flip_record(
            &name,
            &shape,
            "F3 link down at scan start",
            &facts,
            &known,
        ));
        lab.teardown();
    }

    let markdown = unicast_markdown(&records);
    let path = write_artifacts(&name, &records_to_json(&name, &records), &markdown)?;
    println!(
        "iface-flip: {} record(s) — {}",
        records.len(),
        path.display()
    );
    Ok(())
}

/// Spawns the thread that flips the link after `after_ms`.
fn spawn_flip(host_if: &str, after_ms: u64, state: &str) -> thread::JoinHandle<()> {
    let host_if = host_if.to_owned();
    let state = state.to_owned();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(after_ms));
        let _ = Command::new("ip")
            .args(["link", "set", &host_if, &state])
            .status();
    })
}

/// One iface-flip record.
fn flip_record(
    experiment: &str,
    shape: &Shape,
    variant: &str,
    facts: &ScanFacts,
    known: &BTreeSet<Ipv4Addr>,
) -> RunRecord {
    let discovered: BTreeSet<Ipv4Addr> = facts.observations.iter().map(|o| o.ip).collect();
    let hits = discovered.intersection(known).count();
    RunRecord {
        experiment: experiment.to_owned(),
        scenario: shape.name.to_owned(),
        variant: variant.to_owned(),
        cycle: 1,
        date: now_utc(),
        network_type: "netns synthetic (veth pair, user namespaces)",
        scope_size: 254,
        mode: "active",
        rate_pps: DEFAULT_RATE_PPS,
        passes: 2,
        known_devices: known.len(),
        discovered_this_cycle: discovered.len(),
        discovered_cumulative: discovered.len(),
        recall_cumulative_pct: hits as f64 / known.len().max(1) as f64 * 100.0,
        time_to_first_ms: facts.time_to_first_ms,
        packets_sent: facts.counters.requests_sent,
        send_errors: facts.counters.send_errors_transient + facts.counters.send_errors_fatal,
        replies_accepted: facts.counters.replies_accepted,
        rejected_by_reason: rejection_tallies(&facts.counters),
        outcome: facts.outcome.to_string(),
        scan_elapsed_ms: facts.elapsed_ms,
        cpu_ms: facts.cpu_ms,
        notes: format!(
            "send errors: transient {}, fatal {}",
            facts.counters.send_errors_transient, facts.counters.send_errors_fatal
        ),
        ..RunRecord::default()
    }
}

// ---------------------------------------------------------------------------
// The drop-netraw-exec driver (S7(a) pattern, for the read-only
// observation)
// ---------------------------------------------------------------------------

/// `drop-netraw-exec -- <cmd…>` — removes `CAP_NET_RAW` from every
/// capability set (the approved `caps` crate, the exact S7(a) probe
/// pattern) and runs `<cmd>`; its exit status is propagated.
fn cmd_drop_netraw_exec(args: &[String]) -> Result<(), String> {
    let Some(split) = args.iter().position(|arg| arg == "--") else {
        return Err("drop-netraw-exec: expected `-- <command…>`".to_owned());
    };
    let command = args.get(split + 1..).unwrap_or(&[]);
    let Some(program) = command.first() else {
        return Err("drop-netraw-exec: no command after `--`".to_owned());
    };
    let cap = caps::Capability::CAP_NET_RAW;
    for step in [
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Inheritable,
        caps::CapSet::Effective,
        caps::CapSet::Permitted,
    ] {
        caps::drop(None, step, cap)
            .map_err(|err| format!("dropping CAP_NET_RAW from {step:?}: {err}"))?;
    }
    let status = Command::new(program)
        .args(command.get(1..).unwrap_or(&[]))
        .status()
        .map_err(|err| format!("running {program:?}: {err}"))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(format!("the command exited with {code}")),
        None => Err("the command was terminated by a signal".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let args: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let Some(subcommand) = args.get(1).cloned() else {
        eprintln!(
            "usage: poc_measure <grid|sender-ip|unicast|late|transport|neighbor|observe|iface-flip|drop-netraw-exec> [flags]"
        );
        return ExitCode::from(2);
    };
    let rest: Vec<String> = args.get(2..).unwrap_or(&[]).to_vec();
    let result = match subcommand.as_str() {
        "grid" => cmd_grid(&rest),
        "sender-ip" => cmd_sender_ip(&rest),
        "unicast" => cmd_unicast(&rest),
        "late" => cmd_late(&rest),
        "transport" => cmd_transport(&rest),
        "neighbor" => cmd_neighbor(&rest),
        "observe" => cmd_observe(&rest),
        "iface-flip" => cmd_iface_flip(&rest),
        "drop-netraw-exec" => cmd_drop_netraw_exec(&rest),
        other => {
            eprintln!("poc_measure: unknown subcommand {other:?}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("poc_measure {subcommand}: {message}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (the pure layers: args, config text, log parsing, records)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing_is_total() {
        assert!(parse_cidr("192.0.2.0/24").is_ok());
        assert!(parse_cidr("192.0.2.0").is_err());
        assert!(parse_cidr("bogus/24").is_err());
        assert!(parse_cidr("192.0.2.0/33").is_err());
    }

    #[test]
    fn impairment_config_lines_match_the_t106_format() {
        let text = ImpairSpec::p2(42).config_lines();
        for key in [
            "seed 42\n",
            "drop 0.200\n",
            "delay_min_ms 50\n",
            "delay_max_ms 200\n",
            "ignore_first 0\n",
            "answer_fraction 1.000\n",
        ] {
            assert!(text.contains(key), "missing {key:?} in:\n{text}");
        }
    }

    #[test]
    fn profile_seeds_follow_the_t106_scheme() {
        assert_eq!(profile_for("p0").unwrap().seed, MEASURE_BASE);
        assert_eq!(profile_for("p3").unwrap().seed, MEASURE_BASE + 3);
        assert_eq!(
            profile_for("s9-late-400ms").unwrap().seed,
            MEASURE_BASE + 102
        );
        assert!(profile_for("p9").is_err());
    }

    #[test]
    fn answer_generation_matches_the_t106_generator() {
        let answers = answers_from("192.0.2.12", 3, 0x00).unwrap();
        assert_eq!(answers.len(), 3);
        assert_eq!(answers[0].ip.to_string(), "192.0.2.12");
        assert_eq!(answers[0].mac.to_string(), "02:00:00:00:01:0c");
        assert_eq!(answers[2].mac.to_string(), "02:00:00:00:01:0e");
        // A run past the octet boundary is refused, never wrapped.
        assert!(answers_from("192.0.2.250", 10, 0x00).is_err());
    }

    #[test]
    fn shapes_match_the_t106_measurement_shapes() {
        let s1 = Shape::s1().unwrap();
        assert_eq!(s1.known.len(), 20);
        assert_eq!(s1.kernel_addrs.len(), 10);
        let s2 = Shape::s2().unwrap();
        assert_eq!(s2.known.len(), 250);
        assert_eq!(s2.answers.first().unwrap().ip.to_string(), "198.51.100.2");
        let s4 = Shape::s4().unwrap();
        assert_eq!(s4.known.len(), 12);
        let macs: HashSet<MacAddr> = s4.answers.iter().map(|a| a.mac).collect();
        assert_eq!(macs.len(), 1); // one proxy MAC behind 12 IPs
        let s9 = Shape::s9().unwrap();
        assert_eq!(s9.known.len(), 12);
    }

    #[test]
    fn rxlog_parsing_counts_and_spans() {
        let dir = std::env::temp_dir().join("poc-measure-test-rxlog");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("responder.log");
        fs::write(
            &path,
            "# osza-netmon netns responder log v1\n\
             READY iface=v-xb pid=99 seed=1 drop=0.000\n\
             RX t=100 et=0x0806 src=32:5e:d9:91:36:68 dst=ff:ff:ff:ff:ff:ff op=1 sip=192.0.2.1 tip=192.0.2.12 len=42\n\
             TX t=101 kind=answer src=02:00:00:00:01:0c dst=32:5e:d9:91:36:68 sip=192.0.2.12 tip=192.0.2.1\n\
             RX t=110 et=0x0806 src=32:5e:d9:91:36:68 dst=02:00:00:00:01:0c op=1 sip=192.0.2.1 tip=192.0.2.12 len=42\n\
             DROP t=111 ip=192.0.2.13 idx=1 reason=ignore-first\n\
             RX t=120 et=0x1234 src=02:00:00:bb:00:01 dst=ff:ff:ff:ff:ff:ff len=60\n\
             garbage line\n",
        )
        .unwrap();
        let summary = RxSummary::read(&path);
        assert!(summary.ready);
        assert_eq!(summary.rx_total, 3); // two ARP requests + one non-ARP frame
        assert_eq!(summary.requests.len(), 2); // op=1 ARP requests
        assert_eq!(summary.tx_total, 1);
        assert_eq!(summary.answers, 1);
        assert_eq!(summary.drops, 1);
        let per_target = summary.requests_per_target();
        assert_eq!(per_target.get(&"192.0.2.12".parse().unwrap()), Some(&2));
        let span = span_since(&summary, 0, &"32:5e:d9:91:36:68".parse().unwrap(), 100);
        assert_eq!(span, Some(110 - 100 + 10));
    }

    #[test]
    fn log_field_extraction_is_bounded() {
        assert_eq!(field("RX t=12 op=1 x", "op=").as_deref(), Some("1"));
        assert_eq!(field("RX t=12 op=1 x", "t=").as_deref(), Some("12"));
        assert_eq!(field("RX t=12", "missing="), None);
        assert_eq!(number("WITNESS total=5 in=3 outgoing=2", "in="), Some(3));
        // The witness's stdout is parsed whole: the trailing newline
        // must not leak into the last field's value.
        assert_eq!(
            parse_witness("WITNESS total=9 in=7 outgoing=2\n"),
            (Some(7), Some(2))
        );
        assert_eq!(
            parse_witness("WITNESS total=17 in=17 outgoing=0\n"),
            (Some(17), Some(0))
        );
    }

    #[test]
    fn json_escaping_covers_the_basics() {
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("line\n"), "\"line\\n\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn records_json_carries_the_t106_fields() {
        let record = RunRecord {
            experiment: "test".to_owned(),
            scenario: "S1".to_owned(),
            variant: "P0/100pps/2p".to_owned(),
            cycle: 1,
            known_devices: 20,
            discovered_cumulative: 20,
            recall_cumulative_pct: 100.0,
            packets_sent: 486,
            transport_non_arp: Some(42),
            ..RunRecord::default()
        };
        let json = records_to_json("test", &[record]);
        assert!(json.contains("\"recall_cumulative_pct\": 100.00"));
        assert!(json.contains("\"transport_non_arp\": 42"));
        assert!(json.contains("\"rejected_by_reason\": []"));
        assert!(json.contains("\"experiment\": \"test\""));
    }

    #[test]
    fn flag_parsing_helpers() {
        let args = vec![
            "--scenarios".to_owned(),
            "s1,s2".to_owned(),
            "--cycles".to_owned(),
            "3".to_owned(),
        ];
        assert_eq!(value_of(&args, "cycles").as_deref(), Some("3"));
        let list = list_of(&args, "scenarios", &|s| {
            shape_by_name(s).map(|_| s.to_owned())
        })
        .unwrap()
        .unwrap();
        assert_eq!(list, vec!["s1".to_owned(), "s2".to_owned()]);
        let bad = list_of(
            &["--scenarios".to_owned(), "bogus".to_owned()],
            "scenarios",
            &|s| shape_by_name(s).map(|_| s.to_owned()),
        );
        assert!(bad.unwrap().is_err());
        assert_eq!(value_of(&args, "missing"), None);
    }

    #[test]
    fn witness_and_span_math() {
        assert_eq!(
            parse_witness("WITNESS total=0 in=0 outgoing=0"),
            (Some(0), Some(0))
        );
        assert_eq!(parse_witness("no witness line"), (None, None));
    }
}
