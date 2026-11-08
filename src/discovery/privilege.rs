// SPDX-License-Identifier: GPL-3.0-only

//! Privilege handling (plan §4 ADR-005, §7.2 SR-06; task T-104).
//!
//! This module owns the two privilege-sensitive operations of the active
//! discovery path:
//!
//! * [`open_raw_socket`] opens the `AF_PACKET` socket the ARP sweep runs
//!   on. It is the **only** operation in the crate that needs
//!   `CAP_NET_RAW`; everything after it — sending, receiving, parsing —
//!   works on the already-open handle without privileges (ADR-005 step 2).
//! * [`drop_capabilities`] removes every capability from the calling
//!   thread and sets `no_new_privs`, then **verifies** its own work by
//!   reading `/proc/thread-self/status` (SR-06): `CapEff`, `CapPrm`,
//!   `CapInh` and `CapAmb` must all be `0000000000000000` and
//!   `NoNewPrivs` must be `1`. A drop whose verification fails is an
//!   error (fail closed), never a warning.
//!
//! The socket itself is opened by `pnet_datalink` (the provisional
//! ADR-009 transport, behind the [`ArpTransport`](crate::discovery::arp)
//! trait): it creates the `AF_PACKET`/`SOCK_RAW` descriptor, binds it to
//! the named interface and splits it into a send and a receive handle,
//! which [`RawSocket`] owns. The library opens the socket with
//! `ETH_P_ALL`, not `ETH_P_ARP` — the deviation plan §2.1/task card
//! anticipate for libraries that cannot select the protocol; the scanner
//! compensates with a mandatory software EtherType filter (FR-DS-06
//! condition 1 is still enforced by [`parse_arp_reply`](crate::discovery::arp::parse_arp_reply)).
//!
//! Task T-205 adds the informational root check of ADR-005 item 5
//! (assigned by T-104-FU1): [`running_as_root`] reads the effective
//! uid from `/proc/self/status` once at startup (via the pure, total
//! [`parse_effective_uid`]); an unreadable or unparsable file yields
//! `false` — the warning is suppressed when the answer cannot be
//! determined. It is deliberately NOT a capability probe: capabilities
//! are dropped on the socket path regardless of uid, and the check
//! only feeds the §6.8 startup message.
//!
//! Capability manipulation uses the `caps` crate and `no_new_privs` uses
//! `nix::sys::prctl` — both safe wrappers; this crate keeps
//! `#![forbid(unsafe_code)]` (SR-01). Bounding-set clearing is attempted
//! only when `CAP_SETPCAP` is held (it cannot be narrowed otherwise);
//! ADR-005's verification does not cover `CapBnd`, so a bounding set that
//! could not be narrowed is reported, not treated as a failure — with
//! `no_new_privs` set, a residual bounding set cannot re-grant
//! capabilities to this thread or its children.
//!
//! Capability state and `no_new_privs` are **per thread** (Linux
//! semantics). [`drop_capabilities`] must therefore be called on the main
//! thread **before any other thread is spawned**, so the whole process is
//! covered: threads created afterwards inherit the dropped state, while
//! threads created before would keep their capabilities. The example and
//! the future application core (T-205) follow that order.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::sync::PoisonError;

use pnet_datalink::channel;
use pnet_datalink::{Config, DataLinkReceiver, DataLinkSender, NetworkInterface};

/// Bound on the `/proc/thread-self/status` read (plan §7.2 SR-10): the
/// file is a few KiB on any real kernel; the bound only caps pathological
/// content before parsing.
const THREAD_STATUS_MAX_BYTES: u64 = 64 * 1024;

/// Where the calling thread's own capability state is verified (SR-06).
/// `/proc/self/status` reports the *main* thread; `thread-self` reports
/// the calling thread — the one whose capabilities were dropped.
const THREAD_STATUS_PATH: &str = "/proc/thread-self/status";

/// Send-side poll timeout of the raw socket (task card §3.1: "`send` must
/// not block indefinitely"). 50 ms keeps a wedged interface from stalling
/// the pacing loop beyond one cancel slice (FR-DS-09's 250 ms budget).
const SEND_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

/// Receive-side poll granularity of the raw socket: a zero read timeout
/// turns the receiver into a true poll, and [`LinuxArpTransport`](crate::discovery::arp::LinuxArpTransport)
/// adds its own bounded waiting — see that type for the reasoning.
const RECV_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(0);

// ---------------------------------------------------------------------------
// RawSocket
// ---------------------------------------------------------------------------

/// The opened raw socket: an opaque, [`Send`] owner of the datalink
/// handles behind the ARP transport.
///
/// Constructed only by [`open_raw_socket`] and consumed only by the
/// production transport ([`LinuxArpTransport::new`](crate::discovery::arp::LinuxArpTransport::new)):
/// the socket is opened **before** [`drop_capabilities`] runs, and nothing
/// after that point needs a capability (ADR-005 step 2/3 ordering).
///
/// [`Send`]: std::marker::Send
pub struct RawSocket {
    sender: Box<dyn DataLinkSender>,
    receiver: Box<dyn DataLinkReceiver>,
}

impl RawSocket {
    /// Splits the socket into its send and receive halves (crate-internal;
    /// the production transport is the only consumer).
    pub(crate) fn into_handles(self) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
        (self.sender, self.receiver)
    }
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSocket")
            .field("sender", &"DataLinkSender")
            .field("receiver", &"DataLinkReceiver")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors of the privilege boundary (task card §3.3).
///
/// Wording follows the controlled vocabulary of plan §5.4: no verdicts,
/// just what happened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivilegeError {
    /// Opening the raw socket failed with `EPERM`/`EACCES`: the process
    /// does not hold `CAP_NET_RAW`. The caller starts in read-only mode
    /// (ADR-005 step 4).
    #[error("opening the raw socket needs CAP_NET_RAW (permission denied)")]
    PermissionDenied,
    /// No interface with the given name exists.
    #[error("no interface named {name:?} exists")]
    InterfaceNotFound {
        /// The interface name that was looked up.
        name: String,
    },
    /// Opening or binding the raw socket failed for a non-permission
    /// reason (I/O error, unsupported link type, …).
    #[error("opening the raw socket failed: {message}")]
    SocketOpen {
        /// The underlying failure, as text.
        message: String,
    },
    /// A step of the capability drop itself failed (prctl or capset).
    #[error("dropping capabilities failed in step {step:?}: {message}")]
    CapabilityDrop {
        /// Which step failed (`"no_new_privs"`, `"ambient"`, `"bounding"`,
        /// `"inheritable"`, `"effective"`, `"permitted"`).
        step: &'static str,
        /// The underlying failure, as text.
        message: String,
    },
    /// The post-drop verification failed: the status file was unreadable,
    /// unparseable, or showed remaining capabilities / `NoNewPrivs: 0`
    /// (SR-06). Fail closed: the caller must not proceed.
    #[error("capability-drop verification failed: {detail}")]
    VerificationFailed {
        /// What the verification found.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// open_raw_socket
// ---------------------------------------------------------------------------

/// Opens the `AF_PACKET` raw socket bound to `interface_name` (ADR-005
/// step 2, task card §3.3).
///
/// The socket is opened by `pnet_datalink` with `SOCK_RAW` and bound to
/// the interface; the returned [`RawSocket`] owns both directions of the
/// channel. Promiscuous mode is **not** enabled (FR-DS-07: the app must
/// not passively collect other hosts' traffic).
///
/// Error mapping:
///
/// * missing interface → [`PrivilegeError::InterfaceNotFound`];
/// * `EPERM`/`EACCES` from the socket syscall →
///   [`PrivilegeError::PermissionDenied`] (the read-only-mode signal);
/// * any other failure → [`PrivilegeError::SocketOpen`].
///
/// The library opens the socket with `ETH_P_ALL` because it cannot select
/// the EtherType; the mandatory software EtherType filter lives in the
/// scanner's receive loop and [`parse_arp_reply`](crate::discovery::arp::parse_arp_reply)
/// still enforces FR-DS-06 condition 1 (deviation per task card §2.1,
/// reported in the T-104 execution report).
pub fn open_raw_socket(interface_name: &str) -> Result<RawSocket, PrivilegeError> {
    let interface = find_interface(interface_name)?;
    // A 42-byte frame is the largest thing we ever write; the read buffer
    // must cover full Ethernet frames (the socket sees every frame the
    // interface gets, not only ARP). Promiscuous mode stays OFF
    // (FR-DS-07); the channel is built in true-poll mode (see
    // [`LinuxArpTransport::recv`](crate::discovery::arp::LinuxArpTransport::recv)).
    let config = Config {
        write_buffer_size: 64,
        read_buffer_size: 4096,
        read_timeout: Some(RECV_POLL_TIMEOUT),
        write_timeout: Some(SEND_WRITE_TIMEOUT),
        channel_type: pnet_datalink::ChannelType::Layer2,
        promiscuous: false,
        ..Config::default()
    };
    match channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(sender, receiver)) => {
            Ok(RawSocket { sender, receiver })
        }
        // `Channel` is `#[non_exhaustive]`; no other variant exists on
        // Linux, but a future platform variant must not panic the caller.
        Ok(_) => Err(PrivilegeError::SocketOpen {
            message: "the datalink channel opened an unsupported channel kind".to_owned(),
        }),
        Err(err) => Err(open_error(interface_name, &err)),
    }
}

/// Finds the `pnet_datalink` interface record for `interface_name`.
fn find_interface(interface_name: &str) -> Result<NetworkInterface, PrivilegeError> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .ok_or_else(|| PrivilegeError::InterfaceNotFound {
            name: interface_name.to_owned(),
        })
}

/// Maps a channel-open failure onto [`PrivilegeError`].
fn open_error(interface_name: &str, err: &std::io::Error) -> PrivilegeError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        // EPERM/EACCES: no CAP_NET_RAW (ADR-005 step 4 → read-only mode).
        return PrivilegeError::PermissionDenied;
    }
    PrivilegeError::SocketOpen {
        message: format!(
            "AF_PACKET channel for interface {interface_name:?} could not be opened: {err}"
        ),
    }
}

// ---------------------------------------------------------------------------
// drop_capabilities
// ---------------------------------------------------------------------------

/// Drops every capability of the calling thread and sets `no_new_privs`
/// (ADR-005 step 3; task card §3.3).
///
/// Steps, in order:
///
/// 1. `no_new_privs` (prctl via nix) — set first, as ADR-005 lists it;
/// 2. ambient set cleared (prctl `PR_CAP_AMBIENT_CLEAR_ALL`);
/// 3. bounding set narrowed, **only if** `CAP_SETPCAP` is currently
///    effective (prctl `PR_CAPBSET_DROP` needs it; without it the set
///    simply cannot be narrowed — see the module docs for why that is
///    acceptable under `no_new_privs`);
/// 4. inheritable, effective and permitted sets cleared (capset via the
///    `caps` crate);
/// 5. verification (SR-06): `/proc/thread-self/status` must show
///    `CapEff`/`CapPrm`/`CapInh`/`CapAmb` = 0 and `NoNewPrivs: 1`.
///
/// The function is **idempotent**: a thread that holds no capabilities at
/// all (the unprivileged read-only fallback of ADR-005 step 4) succeeds —
/// clearing empty sets and setting `no_new_privs` again are no-ops.
///
/// Per-thread semantics: call this on the **main thread before any other
/// thread is spawned** (see the module docs). The drop is irreversible
/// for the calling thread.
pub fn drop_capabilities() -> Result<(), PrivilegeError> {
    // 1. no_new_privs — cannot be unset once set (prctl semantics).
    nix::sys::prctl::set_no_new_privs().map_err(|err| PrivilegeError::CapabilityDrop {
        step: "no_new_privs",
        message: err.to_string(),
    })?;

    // 2. Ambient set: must go before the permitted/inheritable sets are
    //    emptied (ambient membership requires both).
    caps::clear(None, caps::CapSet::Ambient).map_err(|err| PrivilegeError::CapabilityDrop {
        step: "ambient",
        message: err.to_string(),
    })?;

    // 3. Bounding set — only when the thread can actually narrow it.
    //    `has_cap` failures are tolerated: the conservative reading
    //    ("cannot determine ⇒ assume not held") leaves the bounding set
    //    untouched, which the verification step does not cover anyway.
    if caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_SETPCAP).unwrap_or(false)
    {
        caps::clear(None, caps::CapSet::Bounding).map_err(|err| {
            PrivilegeError::CapabilityDrop {
                step: "bounding",
                message: err.to_string(),
            }
        })?;
    }

    // 4. The three capset-managed sets. Order within the group does not
    //    matter (all end empty); the card's order is kept for review.
    caps::clear(None, caps::CapSet::Inheritable).map_err(|err| PrivilegeError::CapabilityDrop {
        step: "inheritable",
        message: err.to_string(),
    })?;
    caps::clear(None, caps::CapSet::Effective).map_err(|err| PrivilegeError::CapabilityDrop {
        step: "effective",
        message: err.to_string(),
    })?;
    caps::clear(None, caps::CapSet::Permitted).map_err(|err| PrivilegeError::CapabilityDrop {
        step: "permitted",
        message: err.to_string(),
    })?;

    // 5. Verification (SR-06) — fail closed on anything less than all
    //    zeros and NoNewPrivs: 1.
    let status = read_thread_status().map_err(|err| PrivilegeError::VerificationFailed {
        detail: err.to_string(),
    })?;
    verify_dropped(&status).map_err(|detail| PrivilegeError::VerificationFailed { detail })?;

    Ok(())
}

/// Checks the SR-06 verification conditions on a parsed status snapshot.
fn verify_dropped(status: &ThreadCapsStatus) -> Result<(), String> {
    if status.effective != 0
        || status.permitted != 0
        || status.inheritable != 0
        || status.ambient != 0
    {
        return Err(format!(
            "capabilities remain after the drop: CapEff={:016x} CapPrm={:016x} \
             CapInh={:016x} CapAmb={:016x}",
            status.effective, status.permitted, status.inheritable, status.ambient
        ));
    }
    if !status.no_new_privs {
        return Err("NoNewPrivs is 0 after setting it".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// /proc/thread-self/status reading and parsing
// ---------------------------------------------------------------------------

/// The capability-related fields of one thread's `/proc/<tid>/status`
/// (SR-06 verification data).
///
/// `bounding` is parsed for honest reporting (the example prints it) but
/// is **not** part of the drop verification — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCapsStatus {
    /// `CapInh` — inheritable set.
    pub inheritable: u64,
    /// `CapPrm` — permitted set.
    pub permitted: u64,
    /// `CapEff` — effective set.
    pub effective: u64,
    /// `CapBnd` — bounding set (reported, not verified).
    pub bounding: u64,
    /// `CapAmb` — ambient set.
    pub ambient: u64,
    /// `NoNewPrivs` — the prctl flag (1 = set).
    pub no_new_privs: bool,
}

impl fmt::Display for ThreadCapsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CapInh={:016x} CapPrm={:016x} CapEff={:016x} CapBnd={:016x} \
             CapAmb={:016x} NoNewPrivs={}",
            self.inheritable,
            self.permitted,
            self.effective,
            self.bounding,
            self.ambient,
            u8::from(self.no_new_privs)
        )
    }
}

/// Errors while obtaining the calling thread's capability status.
#[derive(Debug, thiserror::Error)]
pub enum ThreadStatusError {
    /// `/proc/thread-self/status` could not be read.
    #[error("reading {THREAD_STATUS_PATH} failed: {source}")]
    Io {
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The file content did not contain a parseable capability picture.
    #[error("parsing the thread status failed: {0}")]
    Parse(#[from] StatusParseError),
}

/// Reads and parses the calling thread's `/proc/thread-self/status`
/// (bounded by `THREAD_STATUS_MAX_BYTES`, SR-10).
pub fn read_thread_status() -> Result<ThreadCapsStatus, ThreadStatusError> {
    let mut content = String::new();
    File::open(THREAD_STATUS_PATH)
        .and_then(|file| {
            file.take(THREAD_STATUS_MAX_BYTES)
                .read_to_string(&mut content)
        })
        .map_err(|source| ThreadStatusError::Io { source })?;
    parse_thread_status(&content).map_err(ThreadStatusError::Parse)
}

/// Bound on the `/proc/self/status` read (SR-10): the file is a few
/// KiB on any real kernel; the bound only caps pathological content
/// before the pure parser sees it.
const SELF_STATUS_MAX_BYTES: u64 = 64 * 1024;

/// Where the process's own uid picture is read (ADR-005 item 5).
/// `/proc/self/status` reports the process (the tgid leader's view),
/// which is what "started as root" means; the thread-specific view
/// stays with [`THREAD_STATUS_PATH`].
const SELF_STATUS_PATH: &str = "/proc/self/status";

/// Whether the process runs with effective uid 0 (ADR-005 item 5,
/// assigned to T-205 by T-104-FU1). Read once at startup from
/// `/proc/self/status` (the "Uid:" line, second field = effective uid),
/// size-bounded and total per SR-10. Informational only: capabilities
/// are dropped on the socket path regardless of uid. An unreadable or
/// unparsable status file yields `false` (the warning is suppressed
/// when the value cannot be determined — documented, honest).
pub fn running_as_root() -> bool {
    let mut content = String::new();
    let read = File::open(SELF_STATUS_PATH).and_then(|file| {
        file.take(SELF_STATUS_MAX_BYTES)
            .read_to_string(&mut content)
    });
    match read {
        Ok(_) => parse_effective_uid(&content) == Some(0),
        Err(_) => false,
    }
}

/// Parses the effective uid out of a `/proc/self/status` text (the
/// pure, total function behind [`running_as_root`], task card §5.10).
///
/// The `Uid:` line has four tab-separated fields — real, **effective**,
/// saved, fs — and the *second* one decides. Everything else in the
/// text is ignored; a missing `Uid:` line, a field count below two, or
/// a non-numeric field yields `None` (never a panic; the file is
/// untrusted input, SR-02/SR-10). Whitespace around values is
/// tolerated, mirroring [`parse_thread_status`].
pub fn parse_effective_uid(content: &str) -> Option<u32> {
    // Last `Uid:` line wins if several exist (the kernel writes one;
    // hostile input may write more — the same overwrite discipline as
    // `parse_thread_status`'s field loop).
    let mut effective_uid: Option<u32> = None;
    for line in content.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        if field != "Uid" {
            continue;
        }
        // The four uid fields are tab-separated; take the second
        // (effective) and parse it decimally.
        effective_uid = value
            .split_whitespace()
            .nth(1)
            .and_then(|effective| effective.parse::<u32>().ok());
    }
    effective_uid
}

/// Why synthetic or hostile status text could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusParseError {
    /// A required field is absent (truncated file, different format).
    #[error("the status text has no {field} line")]
    MissingField {
        /// The absent field (`"CapEff"`, `"NoNewPrivs"`, …).
        field: &'static str,
    },
    /// A field is present but its value is not valid for the field.
    #[error("the {field} line has an invalid value: {found:?}")]
    InvalidValue {
        /// The field whose value was rejected.
        field: &'static str,
        /// The rejected value text (already trimmed).
        found: String,
    },
}

/// Parses the capability-related fields out of a `/proc/<tid>/status`
/// text (the pure, total function of task card §3.3).
///
/// Required fields: `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`
/// (16 hex digits) and `NoNewPrivs` (`0` or `1`). Everything else is
/// ignored; any whitespace around values is tolerated; missing or
/// malformed required fields are errors, never panics (SR-02: the file
/// is untrusted input).
pub fn parse_thread_status(content: &str) -> Result<ThreadCapsStatus, StatusParseError> {
    let mut inheritable: Option<u64> = None;
    let mut permitted: Option<u64> = None;
    let mut effective: Option<u64> = None;
    let mut bounding: Option<u64> = None;
    let mut ambient: Option<u64> = None;
    let mut no_new_privs: Option<bool> = None;

    for line in content.lines() {
        // Fields look like `Name:\tvalue`; tolerate any whitespace run.
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field {
            "CapInh" => inheritable = Some(parse_cap("CapInh", value)?),
            "CapPrm" => permitted = Some(parse_cap("CapPrm", value)?),
            "CapEff" => effective = Some(parse_cap("CapEff", value)?),
            "CapBnd" => bounding = Some(parse_cap("CapBnd", value)?),
            "CapAmb" => ambient = Some(parse_cap("CapAmb", value)?),
            "NoNewPrivs" => {
                no_new_privs = Some(match value {
                    "0" => false,
                    "1" => true,
                    other => {
                        return Err(StatusParseError::InvalidValue {
                            field: "NoNewPrivs",
                            found: other.to_owned(),
                        });
                    }
                });
            }
            _ => {}
        }
    }

    Ok(ThreadCapsStatus {
        inheritable: inheritable.ok_or(missing("CapInh"))?,
        permitted: permitted.ok_or(missing("CapPrm"))?,
        effective: effective.ok_or(missing("CapEff"))?,
        bounding: bounding.ok_or(missing("CapBnd"))?,
        ambient: ambient.ok_or(missing("CapAmb"))?,
        no_new_privs: no_new_privs.ok_or(missing("NoNewPrivs"))?,
    })
}

/// One capability-set field: 16 hex digits (u64), nothing else.
fn parse_cap(field: &'static str, value: &str) -> Result<u64, StatusParseError> {
    u64::from_str_radix(value, 16).map_err(|_| StatusParseError::InvalidValue {
        field,
        found: value.to_owned(),
    })
}

/// The error for one absent required field.
fn missing(field: &'static str) -> StatusParseError {
    StatusParseError::MissingField { field }
}

/// Locks a mutex without panicking on poisoning (plan SR-02: a poisoned
/// lock means another thread panicked while holding it; the data is still
/// consistent enough for our single-writer patterns).
///
/// Crate-internal helper shared by this module's future consumers; kept
/// here so the privilege module stays self-contained.
pub(crate) fn lock_or_recover<T>(lock: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `/proc/<tid>/status` excerpt — synthetic values
    /// (RFC 5737-style documentation range is irrelevant for caps; the
    /// masks below are the well-known full-capability and empty masks).
    const FULL_STATUS: &str = "\
Name:\tpoc_discover
Umask:\t0022
State:\tR (running)
CapInh:\t0000000000000000
CapPrm:\t000001ffffffffff
CapEff:\t000001ffffffffff
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t0
Speculation_Store_Bypass:\tvulnerable
";

    #[test]
    fn parses_a_realistic_status_file() {
        let status = parse_thread_status(FULL_STATUS).expect("valid status text");
        assert_eq!(status.inheritable, 0);
        assert_eq!(status.effective, 0x0000_01ff_ffff_ffff);
        assert_eq!(status.permitted, 0x0000_01ff_ffff_ffff);
        assert_eq!(status.bounding, 0x0000_01ff_ffff_ffff);
        assert_eq!(status.ambient, 0);
        assert!(status.no_new_privs);
        // Display shows the verification picture on one line.
        assert_eq!(
            status.to_string(),
            "CapInh=0000000000000000 CapPrm=000001ffffffffff CapEff=000001ffffffffff \
             CapBnd=000001ffffffffff CapAmb=0000000000000000 NoNewPrivs=1"
        );
    }

    #[test]
    fn parses_the_all_dropped_picture() {
        // Exactly what SR-06 must observe after drop_capabilities.
        let text = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
                    CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n\
                    CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        let status = parse_thread_status(text).expect("valid status text");
        assert!(verify_dropped(&status).is_ok());
        // A residual bounding set is acceptable (documented: not covered).
        assert_eq!(status.bounding, 0x0000_01ff_ffff_ffff);
    }

    #[test]
    fn tolerates_any_whitespace_and_unknown_lines() {
        let text = "garbage line without colon\n\
                    CapEff:   0000000000000000   \n\
                    CapInh: 0\nnope CapPrm: 0\n\
                    CapPrm:\t0\nCapBnd: 0\nCapAmb:0\n\
                    NoNewPrivs: 1\nUnrelated:\tignored\n";
        // "nope CapPrm: 0" has no colon before "CapPrm" — split_once(':')
        // yields field "nope CapPrm", which is unknown and ignored, so the
        // real CapPrm line below must still be found.
        let status = parse_thread_status(text).expect("valid status text");
        assert_eq!(status.effective, 0);
        assert_eq!(status.permitted, 0);
        assert!(status.no_new_privs);
    }

    #[test]
    fn missing_required_fields_are_errors_not_panics() {
        // Every field alone is insufficient.
        for removed in [
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
        ] {
            let text = FULL_STATUS
                .lines()
                .filter(|line| !line.starts_with(removed))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                parse_thread_status(&text).unwrap_err(),
                StatusParseError::MissingField { field: removed },
                "removing {removed}"
            );
        }
        // Empty text: everything missing (CapInh reported first).
        assert_eq!(
            parse_thread_status("").unwrap_err(),
            StatusParseError::MissingField { field: "CapInh" }
        );
    }

    #[test]
    fn malformed_values_are_rejected_without_panicking() {
        // Every value here fails u64-hex or the 0/1 grammar.
        for (field, value) in [
            ("CapEff", "not-hex"),
            ("CapEff", ""),
            ("CapEff", "fffffffffffffffff"), // 17 digits: too long for u64
            ("NoNewPrivs", "2"),
            ("NoNewPrivs", ""),
            ("NoNewPrivs", "true"),
        ] {
            let text = format!(
                "CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n\
                 {field}: {value}\nNoNewPrivs: 1\n"
            );
            let err = parse_thread_status(&text).unwrap_err();
            assert!(
                matches!(err, StatusParseError::InvalidValue { .. }),
                "{field}={value:?} gave {err:?}"
            );
        }
        // Shorter-than-16-digit hex is still a valid u64: accepted.
        let text = "CapInh: 0\nCapPrm: 0\nCapEff: 12345\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: 0\n";
        let status = parse_thread_status(text).expect("12345 is valid hex");
        assert_eq!(status.effective, 0x12345);
        assert!(!status.no_new_privs);
    }

    #[test]
    fn hostile_status_text_never_panics() {
        // Structure-less garbage: every byte offset sliced at every
        // alignment; total parser, no panic (SR-02).
        let hostile = "\u{0}\u{1}:::\n\r\nCapEff:::::\nNoNewPrivs:::\n\u{7f}\\\n\n";
        let mangled: String = hostile.chars().chain("CapEff: zzz".chars()).collect();
        let _ = parse_thread_status(&mangled);
        let _ = parse_thread_status(&hostile.repeat(50));
        // Very long single line (no newline at all).
        let _ = parse_thread_status(&"x".repeat(10_000));
        // No panic is the assertion.
    }

    // ---- §5.10: the ADR-005 item 5 root check (T-205, T-104-FU1) -----------

    /// A realistic `/proc/self/status` excerpt with the `Uid:` line in
    /// its kernel position (the four fields are real, effective,
    /// saved, fs — tab-separated).
    const SELF_STATUS: &str = "\
Name:\tosza-netmon
Umask:\t0022
State:\tS (sleeping)
Tgid:\t4242
Pid:\t4242
PPid:\t1
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
NoNewPrivs:\t0
";

    #[test]
    fn parses_effective_uid_from_a_realistic_status() {
        // A normal user: real = effective = 1000.
        assert_eq!(parse_effective_uid(SELF_STATUS), Some(1000));
        // Root: effective field 0 (a setuid-root process has real 1000,
        // effective 0 — the second field must decide, not the first).
        let setuid_root = SELF_STATUS.replace("Uid:\t1000\t1000", "Uid:\t1000\t0");
        assert_eq!(parse_effective_uid(&setuid_root), Some(0));
        // Full root: all four fields 0.
        let full_root = "Uid:\t0\t0\t0\t0\n".to_owned();
        assert_eq!(parse_effective_uid(&full_root), Some(0));
    }

    #[test]
    fn effective_uid_parse_tolerates_whitespace_and_unknown_lines() {
        // Spaces instead of tabs, trailing space, unknown lines around.
        let text = "Name: x\nUid:  1000  1001  1002  1003  \nOther:\ty\n";
        assert_eq!(parse_effective_uid(text), Some(1001));
        // The last Uid line wins if several exist (kernel writes one;
        // hostile input may write more — total, no panic).
        let two_lines = "Uid:\t0\t5\t0\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_effective_uid(two_lines), Some(1000));
    }

    #[test]
    fn effective_uid_parse_is_total_over_garbage() {
        // Missing Uid line entirely.
        assert_eq!(parse_effective_uid("Name: x\nPid: 1\n"), None);
        // Uid line with only one field (no effective field).
        assert_eq!(parse_effective_uid("Uid:\t1000\n"), None);
        // Uid line with an empty value.
        assert_eq!(parse_effective_uid("Uid:\t\n"), None);
        // Non-numeric fields.
        assert_eq!(parse_effective_uid("Uid:\t1000\troot\t0\t0\n"), None);
        assert_eq!(parse_effective_uid("Uid:\ta\tb\tc\td\n"), None);
        // Negative / overflow values.
        assert_eq!(parse_effective_uid("Uid:\t0\t-1\t0\t0\n"), None);
        assert_eq!(
            parse_effective_uid("Uid:\t0\t4294967296\t0\t0\n"),
            None,
            "u32::MAX + 1 must not parse"
        );
        // Empty text.
        assert_eq!(parse_effective_uid(""), None);
        // Structure-less garbage and a very long line: no panic.
        let hostile = "\u{0}:::\n\r\nUid:::::\n\u{7f}\n";
        let _ = parse_effective_uid(hostile);
        let _ = parse_effective_uid(&"x".repeat(10_000));
        let _ = parse_effective_uid(&hostile.repeat(50));
        // A u32::MAX value parses (the boundary of the type).
        assert_eq!(
            parse_effective_uid("Uid:\t0\t4294967295\t0\t0\n"),
            Some(u32::MAX)
        );
    }

    #[test]
    fn running_as_root_is_total_and_stable() {
        // The totality smoke test the card asks for: two calls agree on
        // this machine (the environment decides *which* answer is
        // honest; the function must merely be total and stable).
        let first = running_as_root();
        let second = running_as_root();
        assert_eq!(first, second, "two reads of /proc/self/status agree");
    }

    #[test]
    fn verify_dropped_catches_every_residual() {
        let clean = ThreadCapsStatus {
            inheritable: 0,
            permitted: 0,
            effective: 0,
            bounding: 0xffff_ffff_ffff,
            ambient: 0,
            no_new_privs: true,
        };
        assert!(verify_dropped(&clean).is_ok());
        for residual in [
            ("CapEff", 1u64),
            ("CapPrm", 1 << 12),
            ("CapInh", 1 << 31),
            ("CapAmb", 1 << 40),
        ] {
            let mut dirty = clean;
            match residual.0 {
                "CapEff" => dirty.effective = residual.1,
                "CapPrm" => dirty.permitted = residual.1,
                "CapInh" => dirty.inheritable = residual.1,
                _ => dirty.ambient = residual.1,
            }
            let err = verify_dropped(&dirty).unwrap_err();
            assert!(err.contains(residual.0), "{err}");
        }
        let mut unset = clean;
        unset.no_new_privs = false;
        assert!(verify_dropped(&unset).unwrap_err().contains("NoNewPrivs"));
    }

    // ---- open_raw_socket -------------------------------------------------

    #[test]
    fn open_raw_socket_reports_a_missing_interface() {
        // Interface lookup happens before any socket syscall, so this is
        // testable unprivileged.
        let err = open_raw_socket("osza-no-such-interface").unwrap_err();
        assert_eq!(
            err,
            PrivilegeError::InterfaceNotFound {
                name: "osza-no-such-interface".to_owned()
            }
        );
    }

    #[test]
    fn open_raw_socket_maps_eperm_to_permission_denied() {
        // Skipped when the test process itself holds CAP_NET_RAW (a
        // privileged runner would open the socket successfully).
        if holds_net_raw() {
            eprintln!("skipping: this test process holds CAP_NET_RAW");
            return;
        }
        // "lo" always exists on Linux; opening its AF_PACKET socket
        // without CAP_NET_RAW yields EPERM.
        let err = open_raw_socket("lo").unwrap_err();
        assert_eq!(err, PrivilegeError::PermissionDenied);
    }

    /// Whether the test process currently holds CAP_NET_RAW (privileged
    /// runners must skip the EPERM test).
    fn holds_net_raw() -> bool {
        caps::read(None, caps::CapSet::Effective)
            .map(|set| set.contains(&caps::Capability::CAP_NET_RAW))
            .unwrap_or(false)
    }

    // ---- drop_capabilities ------------------------------------------------

    #[test]
    fn drop_capabilities_is_idempotent_without_capabilities() {
        // Skipped under a privileged runner: dropping is irreversible for
        // the thread, and the ignored tests below cover that case in a
        // dedicated thread.
        if holds_any_capability() {
            eprintln!("skipping: this test process holds capabilities");
            return;
        }
        // Unprivileged: the drop must succeed twice (idempotent), and the
        // verification must see all-zero capability sets.
        drop_capabilities().expect("drop succeeds without capabilities");
        drop_capabilities().expect("drop is idempotent");
        let status = read_thread_status().expect("thread status is readable");
        assert!(verify_dropped(&status).is_ok(), "{status}");
        assert!(status.no_new_privs);
    }

    /// Whether the test process holds any effective capability.
    fn holds_any_capability() -> bool {
        caps::read(None, caps::CapSet::Effective)
            .map(|set| !set.is_empty())
            .unwrap_or(false)
    }

    // ---- privileged tests (#[ignore]) ------------------------------------
    //
    // The drop is irreversible for the calling thread, so these run the
    // real thing in a dedicated thread. Exact commands (task card §9.1):
    //
    //   sudo cargo test --locked --all-features -- --ignored privilege::
    //
    // or, without real root, inside a user+network namespace:
    //
    //   unshare --user --map-root-user --net \
    //     cargo test --locked --all-features -- --ignored privilege::

    #[test]
    #[ignore = "needs CAP_NET_RAW or a user+net namespace (see the commands above)"]
    fn privileged_open_raw_socket_succeeds_and_drop_verifies() {
        std::thread::Builder::new()
            .name("priv-drop-test".into())
            .spawn(|| {
                // lo always exists on Linux; with CAP_NET_RAW the channel
                // opens (bound, non-promiscuous, Layer 2).
                let socket = open_raw_socket("lo").expect("privileged open succeeds");
                drop(socket);
                // The full drop, verified by reading the thread's own
                // status (SR-06): CapEff/CapPrm/CapInh/CapAmb all zero,
                // NoNewPrivs 1.
                drop_capabilities().expect("verified drop succeeds");
                let status = read_thread_status().expect("status readable");
                assert_eq!(status.effective, 0);
                assert_eq!(status.permitted, 0);
                assert_eq!(status.inheritable, 0);
                assert_eq!(status.ambient, 0);
                assert!(status.no_new_privs, "{status}");
                // With root's CAP_SETPCAP the bounding set was narrowed
                // too (kernel-dependent; reported honestly either way).
            })
            .expect("spawn dedicated thread")
            .join()
            .expect("drop thread must not panic");
    }

    #[test]
    #[ignore = "needs a user+net namespace (see the commands above)"]
    fn privileged_drop_fails_closed_verification_catches_residual() {
        // Synthetic check of the fail-closed path: a status picture with
        // a residual capability must be rejected by verify_dropped even
        // though it came from a "successful" drop sequence.
        let dirty = ThreadCapsStatus {
            inheritable: 0,
            permitted: 0,
            effective: 1 << 13, // CAP_NET_RAW
            bounding: 0,
            ambient: 0,
            no_new_privs: true,
        };
        assert!(verify_dropped(&dirty).is_err());
    }
}
