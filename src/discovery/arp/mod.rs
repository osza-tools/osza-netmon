// SPDX-License-Identifier: GPL-3.0-only

//! The ARP wire format (plan §8.1 `discovery/arp/`; task T-103) and the
//! active ARP sweep of task T-104.
//!
//! [`codec`] is the whole of T-103: the 42-byte Ethernet+ARP request
//! builder (FR-DS-03) and the total, solicited-only reply validator
//! (FR-DS-06) with its rejection counters.
//!
//! T-104 adds the machinery around it, all of it transport-agnostic
//! because ADR-009 (discovery transport library) stays Pending until the
//! T-105 PoC report:
//!
//! * [`transport`] — the [`ArpTransport`] trait
//!   and the provisional `pnet_datalink` implementation;
//! * [`scanner`] — [`ArpScanner`]: target
//!   generation, pacing, passes, concurrent listen, cap, window,
//!   cancellation, outcomes;
//! * [`worker`] — [`ArpWorkerHandle`]: the
//!   background thread with bounded channels and FR-DS-10 batching.
//!
//! Nothing in this module imports from `registry`, `app` or `ui`
//! (plan §8.2); the example wires it to the `net` layer (T-101) and the
//! neighbor table (T-102).

pub mod codec;
pub mod scanner;
pub mod transport;
pub mod worker;

pub use codec::{
    ARP_FRAME_LEN, ArpReply, ArpReplyContext, ArpReplyCounters, InvalidReply, build_arp_request,
    parse_arp_reply,
};
pub use scanner::{
    ArpScanner, DEFAULT_LISTEN_WINDOW, DEFAULT_PASS_GAP, DEFAULT_RATE_PPS, DEFAULT_RESPONSE_CAP,
    MAX_PASSES, MAX_RATE_PPS, Observation, ScanCounters, ScanOutcome, ScanResult,
};
pub use transport::{ArpTransport, LinuxArpTransport, TransportError};
pub use worker::{
    ArpWorkerHandle, COMMAND_CAPACITY, DiscoveryEvent, EVENT_CAPACITY, MAX_BATCH_SIZE, ScanCommand,
    ScanParams, ScanSummary, WorkerError,
};

/// The shared test fixtures of the ARP sweep (task T-104; the same
/// pattern as `model::testing` in T-002).
///
/// [`FakeTransport`] is the in-memory [`ArpTransport`](ArpTransport) the
/// scanner and worker suites drive: it answers requests for scripted
/// responders, delivers replies with an optional delay, can fail sends
/// transiently or fatally, and can park its `recv` like a real socket.
/// All fixtures use synthetic documentation addresses (RFC 5737
/// `192.0.2.0/24`) and locally-administered MACs (`02:…`), per plan
/// §14.3 rule 8.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use super::transport::ArpTransport;
    use super::transport::TransportError;
    use crate::discovery::privilege::lock_or_recover;
    use crate::model::mac::MacAddr;

    /// A reply scheduled for delivery at a specific instant.
    struct QueuedFrame {
        deliver_at: Instant,
        frame: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeState {
        sent: Vec<(Instant, Vec<u8>)>,
        queued: VecDeque<QueuedFrame>,
        responders: Vec<(Ipv4Addr, MacAddr)>,
        reply_delay: Duration,
        /// Time `send` parks *after* queueing the reply — models a slow
        /// driver and lets the receive thread drain the reply before the
        /// sender's post-send bookkeeping runs (deterministic pre-gap
        /// skip-check tests).
        send_lag: Duration,
        send_failures: VecDeque<Option<TransportError>>,
        fail_all_sends: Option<TransportError>,
        fail_recv_with: Option<TransportError>,
        recv_sleeps: bool,
    }

    /// The in-memory [`ArpTransport`](super::ArpTransport) for the
    /// scanner and worker test suites (see the module docs).
    ///
    /// Cloning keeps the shared state, so a test can hold one clone for
    /// assertions while the scanner owns another.
    #[derive(Clone)]
    pub(crate) struct FakeTransport {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeTransport {
        /// An empty, healthy transport: sends succeed, nothing answers.
        pub(crate) fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState::default())),
            }
        }

        /// Answers every request for `ip` with `mac` (immediately, or
        /// after [`reply_delay`](Self::reply_delay)).
        pub(crate) fn responder(&self, ip: Ipv4Addr, mac: MacAddr) {
            lock_or_recover(&self.state).responders.push((ip, mac));
        }

        /// Delays auto-generated replies by `delay`.
        pub(crate) fn reply_delay(&self, delay: Duration) {
            lock_or_recover(&self.state).reply_delay = delay;
        }

        /// Parks `send` for `lag` after the frame (and any reply) was
        /// queued — see [`FakeState::send_lag`].
        pub(crate) fn send_lag(&self, lag: Duration) {
            lock_or_recover(&self.state).send_lag = lag;
        }

        /// Fails the `n`-th send (0-based) with `err`; earlier and later
        /// sends succeed.
        pub(crate) fn fail_send_at(&self, n: usize, err: TransportError) {
            let mut state = lock_or_recover(&self.state);
            while state.send_failures.len() < n {
                state.send_failures.push_back(None);
            }
            state.send_failures.insert(n, Some(err));
        }

        /// Fails every send with `err`.
        pub(crate) fn fail_all_sends(&self, err: TransportError) {
            lock_or_recover(&self.state).fail_all_sends = Some(err);
        }

        /// Makes every `recv` fail fatally with `err`.
        pub(crate) fn fail_recv_with(&self, err: TransportError) {
            lock_or_recover(&self.state).fail_recv_with = Some(err);
        }

        /// Makes empty `recv` calls park for the requested timeout, like
        /// a blocking socket (cancellation-under-recv tests).
        pub(crate) fn recv_sleeps(&self, yes: bool) {
            lock_or_recover(&self.state).recv_sleeps = yes;
        }

        /// Queues one hand-crafted reply frame for immediate delivery.
        pub(crate) fn inject_reply(
            &self,
            our_mac: MacAddr,
            our_ip: Ipv4Addr,
            sender_mac: MacAddr,
            sender_ip: Ipv4Addr,
        ) {
            self.inject_frame(build_reply_frame(our_mac, our_ip, sender_mac, sender_ip));
        }

        /// Queues an arbitrary frame for immediate delivery (hostile or
        /// non-ARP input).
        pub(crate) fn inject_frame(&self, frame: Vec<u8>) {
            let mut state = lock_or_recover(&self.state);
            state.queued.push_back(QueuedFrame {
                deliver_at: Instant::now(),
                frame,
            });
        }

        /// The send log: one `(instant, frame)` per successful send.
        pub(crate) fn sent_log(&self) -> Vec<(Instant, Vec<u8>)> {
            lock_or_recover(&self.state).sent.clone()
        }
    }

    /// The probed IPv4 of a 42-byte request frame (offsets 38..42), or
    /// `None` for anything else (hostile frames never panic the fake).
    fn target_ip_of(frame: &[u8]) -> Option<Ipv4Addr> {
        let bytes: [u8; 4] = frame.get(38..42)?.try_into().ok()?;
        Some(Ipv4Addr::from(u32::from_be_bytes(bytes)))
    }

    impl ArpTransport for FakeTransport {
        fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
            let mut state = lock_or_recover(&self.state);
            if let Some(err) = &state.fail_all_sends {
                return Err(err.clone());
            }
            if let Some(Some(err)) = state.send_failures.pop_front() {
                return Err(err);
            }
            state.sent.push((Instant::now(), frame.to_vec()));
            // Answer requests for known responders: queue a reply for
            // delivery after the configured delay, addressed to the
            // synthetic interface identity (see [`test_our_mac`]).
            if let Some(target) = target_ip_of(frame) {
                let reply_delay = state.reply_delay;
                let replies: Vec<Vec<u8>> = state
                    .responders
                    .iter()
                    .filter(|(ip, _)| *ip == target)
                    .map(|(ip, mac)| build_reply_frame(test_our_mac(), TEST_OUR_IP, *mac, *ip))
                    .collect();
                for frame in replies {
                    state.queued.push_back(QueuedFrame {
                        deliver_at: Instant::now() + reply_delay,
                        frame,
                    });
                }
            }
            let send_lag = state.send_lag;
            if send_lag > Duration::ZERO {
                // Park with the lock released so the receive thread can
                // drain the reply this send just queued.
                drop(state);
                std::thread::sleep(send_lag);
            }
            Ok(())
        }

        fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
            {
                let mut state = lock_or_recover(&self.state);
                if let Some(err) = &state.fail_recv_with {
                    return Err(err.clone());
                }
                let now = Instant::now();
                if let Some(position) = state
                    .queued
                    .iter()
                    .position(|queued| queued.deliver_at <= now)
                    && let Some(queued) = state.queued.remove(position)
                {
                    return Ok(Some(queued.frame));
                }
            }
            // Nothing ready: optionally emulate a blocking socket. The
            // lock was dropped above so the sending thread is never
            // blocked by a parked receiver.
            if timeout > Duration::ZERO && lock_or_recover(&self.state).recv_sleeps {
                std::thread::sleep(timeout);
            }
            Ok(None)
        }
    }

    /// The synthetic interface identity every test that uses the
    /// auto-responder feature constructs its scanner with
    /// (documentation MAC `02:00:00:aa:bb:01`, RFC 5737 address
    /// `192.0.2.1`). Auto-generated replies are addressed to exactly
    /// this identity, so they pass FR-DS-06 conditions 7–11 against the
    /// scanner's own context. Tests that need different identities use
    /// [`inject_reply`](FakeTransport::inject_reply), which takes them
    /// as parameters.
    pub(crate) fn test_our_mac() -> MacAddr {
        MacAddr::from_octets([0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01]).expect("valid unicast MAC")
    }

    /// See [`test_our_mac`].
    pub(crate) const TEST_OUR_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// Builds one well-formed ARP reply frame (42 bytes, Appendix E):
    /// Ethernet dst `our_mac`, src `sender_mac`, ARP sender
    /// `sender_mac`/`sender_ip`, ARP target `our_mac`/`our_ip`.
    pub(crate) fn build_reply_frame(
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&our_mac.octets());
        frame.extend_from_slice(&sender_mac.octets());
        frame.extend_from_slice(&[0x08, 0x06]); // EtherType ARP
        frame.extend_from_slice(&[0x00, 0x01]); // htype Ethernet
        frame.extend_from_slice(&[0x08, 0x00]); // ptype IPv4
        frame.extend_from_slice(&[0x06, 0x04]); // hlen 6, plen 4
        frame.extend_from_slice(&[0x00, 0x02]); // opcode reply
        frame.extend_from_slice(&sender_mac.octets());
        frame.extend_from_slice(&u32::from(sender_ip).to_be_bytes());
        frame.extend_from_slice(&our_mac.octets());
        frame.extend_from_slice(&u32::from(our_ip).to_be_bytes());
        frame
    }
}
