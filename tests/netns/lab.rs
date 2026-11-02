// SPDX-License-Identifier: GPL-3.0-only

//! The lab builder: one veth pair + device-side nested network namespace
//! per scenario (task T-106).
//!
//! This is the T-104 execution report §4.1 recipe (independently
//! reproduced by the T-104 review §1.4) promoted into Rust, unchanged in
//! its security shape:
//!
//! * everything runs inside the caller's `unshare --user --map-root-user
//!   --net` wrapper — user-namespace root supplies `CAP_NET_RAW` and
//!   `CAP_NET_ADMIN`; the harness itself never invokes a privileged
//!   helper, never registers named namespaces (it moves interfaces by
//!   PID — task card §8/AC-13) and never needs host root;
//! * the device side is a nested `unshare --net` child — a `bash -c`
//!   script that publishes its PID, waits for the veth end to appear in
//!   its namespace, configures it (`lo`, `addrgenmode none` to keep IPv6
//!   noise out of the evidence, the kernel-answered addresses) and then
//!   `exec`s this same test binary in `--responder` mode;
//! * the parent moves the device-side veth end with
//!   `ip link set <name> netns <pid>`;
//! * all addresses are RFC 5737 documentation addresses; every synthetic
//!   MAC is locally administered (`02:…`) — plan §14.3 rules 7/8.
//!
//! Teardown always runs (`Drop`): kill the child, delete the host-side
//! veth (both ends disappear with the namespaces). Interface names are
//! per-scenario constants, and the scenario runner serializes labs, so
//! no cross-test interference is possible (task card §5.2).

use std::io::Read as _;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use osza_netmon::model::MacAddr;
use osza_netmon::model::ipv4::Ipv4Net;
use osza_netmon::net::interfaces::enumerate_interfaces;

use crate::config::Answer;
use crate::config::Hostile;
use crate::config::Impairment;
use crate::config::ResponderConfig;
use crate::rxlog::RxLog;

/// Bounded wait for lab setup steps (PID file, readiness line).
const SETUP_WAIT: Duration = Duration::from_secs(10);

/// Poll granularity during bounded waits.
const POLL: Duration = Duration::from_millis(20);

/// What one scenario needs from the lab (the "what to build" spec).
#[derive(Debug, Clone)]
pub struct LabSpec {
    /// Short scenario tag (`s1`, `s5flood`, …) — names the veth pair
    /// (`v-<tag>a` / `v-<tag>b`) and the artifact directory.
    pub tag: &'static str,
    /// The lab's subnet (an RFC 5737 block; `.1`-style host address is
    /// derived: `network + 1` is the scanner side).
    pub subnet: Ipv4Net,
    /// Addresses configured on the device-side veth — the *kernel* of
    /// the device namespace answers for these with the veth's MAC.
    pub kernel_addrs: Vec<Ipv4Addr>,
    /// The responder's answer table (synthetic-MAC devices; may be
    /// empty — the responder then only logs).
    pub answers: Vec<Answer>,
    /// The seeded impairment (P0–P3, S9 variants).
    pub impairment: Impairment,
    /// The hostile mode (S5; `None` elsewhere).
    pub hostile: Hostile,
}

impl LabSpec {
    /// The scanner-side (host) address: `network + 1`.
    pub fn host_ip(&self) -> Ipv4Addr {
        bump(self.subnet.network(), 1)
    }

    /// The device-side veth end's name.
    pub fn peer_if(&self) -> String {
        format!("v-{}b", self.tag)
    }

    /// The scanner-side veth end's name.
    pub fn host_if(&self) -> String {
        format!("v-{}a", self.tag)
    }
}

/// A live lab: handles for teardown plus the facts the scanner needs.
pub struct Lab {
    /// The scanner-side interface name (e.g. `v-s1a`).
    pub host_if: String,
    /// The scan scope (the lab's subnet).
    pub scope: Ipv4Net,
    /// The scanner-side address (`network + 1`).
    pub our_ip: Ipv4Addr,
    /// The scanner-side veth MAC (as enumerated on this namespace).
    pub our_mac: MacAddr,
    /// The receive-log path (read it while live or after teardown).
    pub log_path: PathBuf,
    child: Option<Child>,
}

impl Lab {
    /// Builds the lab: veth pair, nested device namespace, responder.
    ///
    /// Panics (this is test code) with a precise message on any setup
    /// failure — including the responder's own log when it failed to
    /// become ready, so the evidence is in the failure output.
    pub fn build(spec: &LabSpec) -> Lab {
        let artifacts = artifacts_dir(spec.tag);
        // Fresh artifacts per build: a stale PID file or READY line from
        // a previous lab would race this one's setup.
        let _ = std::fs::remove_dir_all(&artifacts);
        std::fs::create_dir_all(&artifacts).unwrap_or_else(|err| {
            panic!("lab {}: creating {}: {err}", spec.tag, artifacts.display())
        });

        let host_if = spec.host_if();
        let peer_if = spec.peer_if();
        let host_ip = spec.host_ip();
        let prefix = spec.subnet.prefix_len();

        // 1. The veth pair and the host side (this namespace).
        run_ip(
            &[
                "link", "add", &host_if, "type", "veth", "peer", "name", &peer_if,
            ],
            &format!("lab {}: creating the veth pair", spec.tag),
        );
        run_ip(
            &[
                "addr",
                "add",
                &format!("{host_ip}/{prefix}"),
                "dev",
                &host_if,
            ],
            &format!("lab {}: configuring {host_if}", spec.tag),
        );
        run_ip(
            &["link", "set", &host_if, "addrgenmode", "none"],
            &format!("lab {}: disabling IPv6 generation on {host_if}", spec.tag),
        );
        run_ip(
            &["link", "set", &host_if, "up"],
            &format!("lab {}: bringing {host_if} up", spec.tag),
        );

        // 2. The responder config + log paths.
        let config_path = artifacts.join("responder.conf");
        let log_path = artifacts.join("responder.log");
        let config = ResponderConfig {
            iface: peer_if.clone(),
            impairment: spec.impairment,
            hostile: spec.hostile,
            answers: spec.answers.clone(),
        };
        std::fs::write(&config_path, config.to_text())
            .unwrap_or_else(|err| panic!("lab {}: writing config: {err}", spec.tag));

        // 3. The device-side child: nested `unshare --net`, bash config
        //    script, then `exec` of this binary in responder mode.
        let pid_path = artifacts.join("child.pid");
        let exe = std::env::current_exe()
            .unwrap_or_else(|err| panic!("lab {}: locating this test binary: {err}", spec.tag));
        let script = device_script(&spec.kernel_addrs, prefix);
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
            .unwrap_or_else(|err| panic!("lab {}: spawning the device namespace: {err}", spec.tag));

        // 4. Move the device-side veth end into the child's namespace.
        let pid = wait_for_pid_file(&pid_path, spec.tag);
        run_ip(
            &["link", "set", &peer_if, "netns", &pid.to_string()],
            &format!(
                "lab {}: moving {peer_if} into the device namespace",
                spec.tag
            ),
        );

        // 5. Wait for the responder's READY line (bounded; the child's
        //    early exit is surfaced immediately via try_wait).
        wait_for_ready(&log_path, spec.tag, &mut child);

        // 6. Read our own interface facts with the production enumerator
        //    (T-101) — the same source the application uses.
        let info = enumerate_interfaces()
            .into_iter()
            .find(|info| info.name() == host_if)
            .unwrap_or_else(|| panic!("lab {}: {host_if} not enumerated", spec.tag));
        let our_mac = info
            .mac()
            .unwrap_or_else(|| panic!("lab {}: {host_if} has no MAC", spec.tag));
        let our_ip = info
            .ipv4()
            .unwrap_or_else(|| panic!("lab {}: {host_if} has no IPv4 address", spec.tag));

        Lab {
            host_if,
            scope: spec.subnet,
            our_ip,
            our_mac,
            log_path,
            child: Some(child),
        }
        .with_child_pid_evidence(&artifacts, pid)
    }

    /// Reads (and parses) the responder's receive log.
    pub fn rxlog(&self) -> RxLog {
        RxLog::read(&self.log_path)
            .unwrap_or_else(|err| panic!("lab {}: reading the receive log: {err}", self.host_if))
    }

    /// Kills the device-side child and deletes the host-side veth end.
    /// Both ends of the pair vanish with the namespaces; idempotent.
    pub fn teardown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_if])
            .status();
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Records the child PID next to the artifacts (evidence).
impl Lab {
    fn with_child_pid_evidence(self, artifacts: &Path, pid: u32) -> Self {
        let _ = std::fs::write(artifacts.join("child-pid.txt"), pid.to_string());
        self
    }
}

/// The device-side bash script (runs inside the nested `unshare --net`).
///
/// Publishes its PID, waits (bounded) for the veth end to appear in its
/// namespace (the parent moves it right after spawn), configures `lo`
/// and the interface (IPv6 address generation off, kernel-answered
/// addresses), then `exec`s the responder.
fn device_script(kernel_addrs: &[Ipv4Addr], prefix: u8) -> String {
    let mut script = String::from(
        "set -e\n\
         echo $$ > \"$OZ_PIDFILE\"\n\
         i=0\n\
         while [ \"$i\" -lt 500 ] && ! ip link show \"$OZ_IFACE\" >/dev/null 2>&1; do\n\
         \tsleep 0.02; i=$((i+1))\n\
         done\n\
         ip link show \"$OZ_IFACE\" >/dev/null 2>&1 || { echo 'device veth never appeared' >&2; exit 3; }\n\
         ip link set lo up\n\
         ip link set \"$OZ_IFACE\" addrgenmode none\n\
         ip link set \"$OZ_IFACE\" up\n",
    );
    for addr in kernel_addrs {
        script.push_str(&format!(
            "ip addr add \"{addr}/{prefix}\" dev \"$OZ_IFACE\"\n"
        ));
    }
    script.push_str("exec \"$OZ_EXE\" --responder --config \"$OZ_CONFIG\" --log \"$OZ_LOG\"\n");
    script
}

/// Runs `ip` and panics (test code) with `context` on failure.
fn run_ip(args: &[&str], context: &str) {
    let output = Command::new("ip").args(args).output();
    let output = match output {
        Ok(output) => output,
        Err(err) => panic!("{context}: spawning ip: {err}"),
    };
    if !output.status.success() {
        panic!(
            "{context}: ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}

/// Waits (bounded) for the child's PID file.
fn wait_for_pid_file(path: &Path, tag: &str) -> u32 {
    let deadline = Instant::now() + SETUP_WAIT;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            return pid;
        }
        std::thread::sleep(POLL);
    }
    panic!("lab {tag}: the device namespace never published its PID");
}

/// Waits (bounded) for the responder's READY line in the log; an early
/// child exit (script failure) fails fast with the log as evidence.
fn wait_for_ready(log_path: &Path, tag: &str, child: &mut Child) {
    let deadline = Instant::now() + SETUP_WAIT;
    let mut last_seen = String::new();
    while Instant::now() < deadline {
        if let Ok(log) = RxLog::read(log_path) {
            if log.ready.is_some() {
                return;
            }
            if let Some(note) = log.notes.iter().find(|note| note.contains("fatal")) {
                panic!("lab {tag}: the responder failed to start: {note}");
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            panic!("lab {tag}: the device-side child exited early with {status}; log:\n{log}");
        }
        if let Ok(text) = std::fs::read_to_string(log_path) {
            last_seen = text;
        }
        std::thread::sleep(POLL);
    }
    panic!("lab {tag}: the responder never became ready; log so far:\n{last_seen}");
}

/// The artifact directory of a scenario under `target/netns/`.
pub fn artifacts_dir(tag: &str) -> PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    dir.push("target");
    dir.push("netns");
    dir.push(tag);
    dir
}

/// `ip + offset` on the IPv4 last octet (lab subnets are /24s or /28s;
/// the offset never crosses the third octet in this harness).
fn bump(ip: Ipv4Addr, offset: u8) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + offset)
}

/// Parses `a.b.c.d/prefix` into an [`Ipv4Net`] (the model type has no
/// `FromStr`; this is the harness's tiny total parser).
pub fn parse_cidr(text: &str) -> Result<Ipv4Net, String> {
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

/// Reads the caller process's CPU time (user + system, in milliseconds)
/// from `/proc/self/stat` — the measurement's CPU-time field
/// (Appendix D per-run record).
pub fn process_cpu_ms() -> Option<u64> {
    let mut text = String::new();
    let mut file = std::fs::File::open("/proc/self/stat").ok()?;
    file.read_to_string(&mut text).ok()?;
    // Fields 14/15 (utime/stime) sit after the comm field, which is
    // parenthesized and may contain spaces: parse after the last ')'.
    let after = text.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // after ')': state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
    // flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11)
    // stime(12) …
    let utime: u64 = fields.get(11).and_then(|v| v.parse().ok())?;
    let stime: u64 = fields.get(12).and_then(|v| v.parse().ok())?;
    let ticks_to_ms = 1000.0 / 100.0; // USER_HZ == 100 on Linux
    Some(((utime + stime) as f64 * ticks_to_ms).round() as u64)
}
