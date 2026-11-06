// SPDX-License-Identifier: GPL-3.0-only

//! The ARP transport boundary (plan §4 ADR-009 Pending, §8.6; task
//! T-104).
//!
//! [`ArpTransport`] is the trait the scanner sweeps through: object-safe,
//! [`Send`] + [`Sync`], and transport-agnostic — no socket type, no
//! library type, no file descriptor appears in it or in
//! [`TransportError`]. ADR-009 (which transport library to use) stays
//! Pending until the T-105 measurement campaign; the production
//! implementation here ([`LinuxArpTransport`], backed by `pnet_datalink`)
//! is therefore **provisional** and replaceable in this one module.
//!
//! The trait is shared by two threads at once (the scanner's sending
//! thread and its receive thread, plan §8.3), which is why it takes
//! `&self` and requires [`Send`] + [`Sync`]. The production transport
//! keeps the two directions in **separate locks**: a single lock around
//! both would let a blocked receive stall the send side and break pacing
//! (FR-DS-04).
//!
//! Error policy (task card §3.1): [`TransportError`] separates **fatal**
//! failures (interface down/removed, socket closed, permission lost —
//! these end the scan with outcome `Failed`) from **transient** ones
//! (`ENOBUFS`, `EAGAIN`, `EINTR` — counted and tolerated). Unknown I/O
//! errors classify as fatal: the conservative choice for a tool whose
//! honest failure modes matter more than its uptime (deviation noted in
//! the T-104 execution report).
//!
//! [`Send`]: std::marker::Send
//! [`Sync`]: std::marker::Sync

use std::fmt;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pnet_datalink::{DataLinkReceiver, DataLinkSender};

use crate::discovery::privilege::RawSocket;
use crate::discovery::privilege::lock_or_recover;

/// How long one receive iteration may park waiting for a frame when the
/// caller asked for a longer timeout (see [`LinuxArpTransport::recv`]).
///
/// 1 ms bounds frame-detection latency and keeps the receive thread's
/// wakeup rate at ~1 kHz *during an active scan only*; the idle app never
/// runs a transport at all.
const RECV_PARK_SLICE: Duration = Duration::from_millis(1);

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// The byte pipe the ARP scanner sweeps through (plan §8.6; task card
/// §3.1).
///
/// * [`send`](ArpTransport::send) writes one complete Ethernet+ARP
///   request frame. It must not block indefinitely (the production
///   implementation arms a send timeout); a zero-length frame is a
///   transient error, not a panic.
/// * [`recv`](ArpTransport::recv) returns one frame if one arrives within
///   `timeout`, [`None`] on timeout. `timeout` must be honored from
///   above — a zero timeout is a poll — and is never exceeded by more
///   than the implementation's documented granularity.
///
/// Implementations must be usable from two threads concurrently, hence
/// the [`Send`] + [`Sync`] supertraits and the `&self` methods.
///
/// [`Send`]: std::marker::Send
/// [`Sync`]: std::marker::Sync
pub trait ArpTransport: Send + Sync {
    /// Sends one frame; see the trait docs.
    fn send(&self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receives one frame within `timeout`; see the trait docs.
    fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Transport failures, split into fatal and transient (task card §3.1).
///
/// The scanner maps the classes onto outcomes: a fatal error ends the
/// scan with `Failed` (FR-DS-11), a transient send error is counted and
/// the scan continues (becoming `Partial` if it happened at all).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// **Fatal**: the network interface went down or was removed
    /// (`ENETDOWN`/`ENODEV`).
    #[error("the network interface went down or was removed")]
    InterfaceLost,
    /// **Fatal**: the transport socket was closed (`EBADF`).
    #[error("the transport socket was closed")]
    SocketClosed,
    /// **Fatal**: permission to use the socket was lost (`EPERM`/`EACCES`
    /// after the socket was already open).
    #[error("permission to use the transport socket was lost")]
    PermissionLost,
    /// **Fatal**: an I/O error the classification does not recognize;
    /// conservative fail-closed (see the module docs).
    #[error("fatal transport failure: {message}")]
    FatalIo {
        /// The underlying failure, as text.
        message: String,
    },
    /// **Transient**: the send buffer was full (`ENOBUFS`); the frame was
    /// dropped by the kernel.
    #[error("the send buffer was full; the frame was dropped")]
    SendBufferFull,
    /// **Transient**: resource temporarily unavailable
    /// (`EAGAIN`/`EWOULDBLOCK`).
    #[error("resource temporarily unavailable")]
    WouldBlock,
    /// **Transient**: the operation was interrupted (`EINTR`).
    #[error("the operation was interrupted")]
    Interrupted,
    /// **Transient**: waiting for writability timed out (the send timeout
    /// armed by the production transport).
    #[error("sending timed out waiting for the interface to accept a frame")]
    SendTimedOut,
}

impl TransportError {
    /// `true` for the fatal class (the scan must stop), `false` for the
    /// transient class (count and continue).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TransportError::InterfaceLost
                | TransportError::SocketClosed
                | TransportError::PermissionLost
                | TransportError::FatalIo { .. }
        )
    }

    /// Classifies an I/O error from the datalink layer.
    ///
    /// Total: any error maps to exactly one variant; unknowns are fatal
    /// (fail closed).
    pub fn from_io(err: &io::Error) -> Self {
        use std::io::ErrorKind;
        match err.raw_os_error() {
            // EPERM (1) / EACCES (13): privileges lost mid-scan.
            Some(1) | Some(13) => TransportError::PermissionLost,
            // ENOBUFS (105): transient send-buffer exhaustion.
            Some(105) => TransportError::SendBufferFull,
            // ENETDOWN (100) / ENODEV (19): the interface is gone.
            Some(100) | Some(19) => TransportError::InterfaceLost,
            // EBADF (9): the descriptor was closed.
            Some(9) => TransportError::SocketClosed,
            _ => match err.kind() {
                ErrorKind::WouldBlock => TransportError::WouldBlock,
                ErrorKind::Interrupted => TransportError::Interrupted,
                ErrorKind::PermissionDenied => TransportError::PermissionLost,
                ErrorKind::TimedOut => TransportError::SendTimedOut,
                // pnet_datalink's Linux backend reports an opaque
                // "Unexpected poll event" error (no errno, kind `Other`)
                // when its poll(2) on the channel's fd returns an
                // unexpected revents set — in practice the interface
                // went down or was removed mid-scan. Mapped to the
                // honest interface-lost classification instead of the
                // generic fatal one since T-204 (ADR-009 consequence
                // note; T-105 follow-up 3, task card §3.4).
                _ if err.to_string().contains("Unexpected poll event") => {
                    TransportError::InterfaceLost
                }
                _ => TransportError::FatalIo {
                    message: err.to_string(),
                },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Production implementation
// ---------------------------------------------------------------------------

/// The production [`ArpTransport`]: `pnet_datalink`'s Linux `AF_PACKET`
/// channel behind the trait (provisional per ADR-009; task card §3.1).
///
/// Constructed from the [`RawSocket`] that
/// [`open_raw_socket`](crate::discovery::privilege::open_raw_socket)
/// opened **before** the capability drop, so nothing the transport does
/// afterwards needs a privilege (ADR-005 ordering).
///
/// The two channel halves sit in **separate mutexes**: the receive thread
/// may hold its lock for up to the caller's timeout while the sending
/// thread sends concurrently (a single shared lock would couple the two
/// directions and break pacing).
///
/// Receive granularity: `pnet_datalink` fixes its poll timeout at channel
/// construction, so the channel is built in true-poll mode (read timeout
/// zero) and this implementation adds the wait itself: [`recv`] polls,
/// then parks in `RECV_PARK_SLICE` slices until the caller's deadline.
/// A `timeout` of zero is therefore exactly one non-blocking poll; a
/// longer timeout is honored within one park slice (1 ms) of overshoot.
///
/// [`recv`]: LinuxArpTransport::recv
pub struct LinuxArpTransport {
    sender: Mutex<Box<dyn DataLinkSender>>,
    receiver: Mutex<Box<dyn DataLinkReceiver>>,
}

impl LinuxArpTransport {
    /// Takes ownership of an already-open [`RawSocket`] (the halves move
    /// in; nothing is re-opened).
    pub fn new(socket: RawSocket) -> Self {
        let (sender, receiver) = socket.into_handles();
        Self {
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver),
        }
    }
}

impl fmt::Debug for LinuxArpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxArpTransport")
            .field("sender", &"DataLinkSender")
            .field("receiver", &"DataLinkReceiver")
            .finish()
    }
}

impl ArpTransport for LinuxArpTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.is_empty() {
            // Defensive: the codec always builds 42-byte frames; an empty
            // frame would be a caller bug, reported not panicked.
            return Err(TransportError::FatalIo {
                message: "refusing to send an empty frame".to_owned(),
            });
        }
        let mut sender = lock_or_recover(&self.sender);
        // pnet's Linux send_to: poll(POLLOUT) with the configured write
        // timeout, then sendto(2). `None` (operation not even attempted)
        // does not occur on Linux but is handled conservatively.
        match sender.send_to(frame, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(err)) => Err(TransportError::from_io(&err)),
            None => Err(TransportError::FatalIo {
                message: "the datalink sender refused the frame".to_owned(),
            }),
        }
    }

    fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        let start = Instant::now();
        loop {
            {
                let mut receiver = lock_or_recover(&self.receiver);
                // Channel read timeout is zero (true poll): next() either
                // returns a frame immediately or reports no data.
                match receiver.next() {
                    Ok(frame) => {
                        // Copy out under the lock: next()'s borrow ends
                        // with the guard.
                        return Ok(Some(frame.to_vec()));
                    }
                    Err(err) => match TransportError::from_io(&err) {
                        // No data right now (poll returned nothing) or a
                        // spurious wakeup: fall through to the deadline
                        // check below.
                        TransportError::WouldBlock
                        | TransportError::Interrupted
                        | TransportError::SendTimedOut => {}
                        fatal_or_unknown => return Err(fatal_or_unknown),
                    },
                }
            }
            let elapsed = start.elapsed();
            if timeout.is_zero() || elapsed >= timeout {
                return Ok(None);
            }
            // Park briefly: bounded frame-detection latency, bounded
            // overshoot past the caller's timeout, no busy spin.
            let remaining = timeout - elapsed;
            std::thread::sleep(remaining.min(RECV_PARK_SLICE));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory transport: one queue of frames to receive, a log of
    /// sent frames, and optional scripted failures. Used by this
    /// module's tests; the scanner/worker suites use the richer fake in
    /// `arp::test_support`.
    #[derive(Default)]
    struct MockTransport {
        incoming: Mutex<Vec<Vec<u8>>>,
        sent: Mutex<Vec<Vec<u8>>>,
        fail_sends_with: Mutex<Vec<Option<TransportError>>>,
    }

    impl MockTransport {
        fn push_incoming(&self, frame: &[u8]) {
            lock_or_recover(&self.incoming).push(frame.to_vec());
        }

        fn sent_frames(&self) -> Vec<Vec<u8>> {
            lock_or_recover(&self.sent).clone()
        }
    }

    impl ArpTransport for MockTransport {
        fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
            let mut failures = lock_or_recover(&self.fail_sends_with);
            if !failures.is_empty()
                && let Some(err) = failures.remove(0)
            {
                return Err(err);
            }
            lock_or_recover(&self.sent).push(frame.to_vec());
            Ok(())
        }

        fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
            let mut incoming = lock_or_recover(&self.incoming);
            if incoming.is_empty() {
                // Simulate a blocking receive for the requested span so
                // the timeout contract is exercised with real waits.
                drop(incoming);
                if !timeout.is_zero() {
                    std::thread::sleep(timeout);
                }
                return Ok(None);
            }
            Ok(Some(incoming.remove(0)))
        }
    }

    #[test]
    fn trait_objects_are_object_safe_and_shareable() {
        // AC-1: `&dyn ArpTransport` and `Box<dyn ArpTransport>` move
        // across threads — compile-time proof that the trait object is
        // Send + Sync (the supertraits make it so).
        fn references_dyn(t: &dyn ArpTransport) {
            fn assert_send_sync<T: Send + Sync + ?Sized>(_: &T) {}
            assert_send_sync(t);
        }
        let mock: Box<dyn ArpTransport> = Box::new(MockTransport::default());
        references_dyn(mock.as_ref());
        let handle = std::thread::spawn(move || {
            let owned: Box<dyn ArpTransport> = mock;
            owned.send(&[0x00])
        });
        handle.join().expect("thread must join").expect("send ok");
    }

    #[test]
    fn mock_send_and_recv_round_trip() {
        let mock = MockTransport::default();
        mock.push_incoming(&[0xaa, 0xbb]);
        assert_eq!(
            mock.recv(Duration::from_millis(1)).expect("recv ok"),
            Some(vec![0xaa, 0xbb])
        );
        mock.send(&[0x01, 0x02]).expect("send ok");
        assert_eq!(mock.sent_frames(), vec![vec![0x01, 0x02]]);
    }

    #[test]
    fn recv_zero_timeout_is_a_poll_not_a_wait() {
        let mock = MockTransport::default();
        let started = Instant::now();
        assert_eq!(
            mock.recv(Duration::ZERO).expect("recv ok"),
            None,
            "empty queue returns None"
        );
        // A poll must not sleep: well under the 1 ms park slice.
        assert!(
            started.elapsed() < Duration::from_millis(1),
            "zero timeout returned after {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn recv_returns_framed_data_in_fifo_order() {
        let mock = MockTransport::default();
        mock.push_incoming(&[1]);
        mock.push_incoming(&[2]);
        mock.push_incoming(&[3]);
        for expected in [1u8, 2, 3] {
            assert_eq!(
                mock.recv(Duration::ZERO).expect("recv ok"),
                Some(vec![expected])
            );
        }
        assert_eq!(mock.recv(Duration::ZERO).expect("recv ok"), None);
    }

    #[test]
    fn scripted_send_errors_surface_unmodified() {
        let mock = MockTransport::default();
        lock_or_recover(&mock.fail_sends_with).extend([Some(TransportError::SendBufferFull), None]);
        assert_eq!(
            mock.send(&[0x00]).unwrap_err(),
            TransportError::SendBufferFull
        );
        mock.send(&[0x01]).expect("second send succeeds");
        assert_eq!(mock.sent_frames(), vec![vec![0x01]]);
    }

    // ---- error classification ---------------------------------------------

    #[test]
    fn io_errors_classify_into_fatal_and_transient() {
        fn classified(raw: Option<i32>, kind: io::ErrorKind) -> TransportError {
            let err = match raw {
                Some(code) => io::Error::from_raw_os_error(code),
                None => io::Error::new(kind, "synthetic"),
            };
            TransportError::from_io(&err)
        }
        // Fatal class.
        let table: [(Option<i32>, io::ErrorKind, TransportError); 8] = [
            (
                Some(100),
                io::ErrorKind::Other,
                TransportError::InterfaceLost,
            ), // ENETDOWN
            (
                Some(19),
                io::ErrorKind::Other,
                TransportError::InterfaceLost,
            ), // ENODEV
            (Some(9), io::ErrorKind::Other, TransportError::SocketClosed), // EBADF
            (
                Some(1),
                io::ErrorKind::Other,
                TransportError::PermissionLost,
            ), // EPERM
            (
                Some(13),
                io::ErrorKind::Other,
                TransportError::PermissionLost,
            ), // EACCES
            (
                Some(5),
                io::ErrorKind::Other,
                TransportError::FatalIo {
                    message: String::new(),
                }, // EIO → fatal
            ),
            (
                None,
                io::ErrorKind::ConnectionReset,
                TransportError::FatalIo {
                    message: String::new(),
                },
            ),
            (
                None,
                io::ErrorKind::PermissionDenied,
                TransportError::PermissionLost,
            ),
        ];
        for (raw, kind, expected) in table {
            let got = classified(raw, kind);
            assert!(got.is_fatal(), "{got:?} must be fatal");
            match (&got, &expected) {
                (TransportError::FatalIo { .. }, TransportError::FatalIo { .. }) => {}
                _ => assert_eq!(got, expected),
            }
        }
        // Transient class.
        let transient: [(Option<i32>, io::ErrorKind, TransportError); 4] = [
            (
                Some(105),
                io::ErrorKind::Other,
                TransportError::SendBufferFull,
            ), // ENOBUFS
            (Some(11), io::ErrorKind::Other, TransportError::WouldBlock), // EAGAIN
            (None, io::ErrorKind::WouldBlock, TransportError::WouldBlock),
            (
                None,
                io::ErrorKind::Interrupted,
                TransportError::Interrupted,
            ),
        ];
        for (raw, kind, expected) in transient {
            let got = classified(raw, kind);
            assert!(!got.is_fatal(), "{got:?} must be transient");
            assert_eq!(got, expected);
        }
        // Send timeout (pnet reports TimedOut when its POLLOUT poll
        // expires) is transient.
        let timed_out = classified(None, io::ErrorKind::TimedOut);
        assert_eq!(timed_out, TransportError::SendTimedOut);
        assert!(!timed_out.is_fatal());
    }

    #[test]
    fn pnet_datalinks_opaque_fatal_poll_error_maps_to_interface_lost() {
        // T-105 follow-up 3 (applied by T-204): pnet_datalink's Linux
        // backend reports "Unexpected poll event" as an untyped
        // io::Error (no errno, kind Other) when its poll(2) sees an
        // unexpected revents set — in practice the interface went down
        // or was removed mid-scan (observed live in the T-105 campaign,
        // report §10 "limitations" note). The honest classification is
        // InterfaceLost, not the generic FatalIo.
        let err = io::Error::other("Unexpected poll event");
        let classified = TransportError::from_io(&err);
        assert_eq!(classified, TransportError::InterfaceLost);
        assert!(classified.is_fatal(), "interface loss is fatal");
        assert_eq!(
            classified.to_string(),
            "the network interface went down or was removed"
        );
        // The mapping matches on the message, so it must not swallow
        // other untyped errors: a different `Other` error still falls
        // through to the conservative fatal classification.
        let other = io::Error::other("something else entirely");
        assert_eq!(
            TransportError::from_io(&other),
            TransportError::FatalIo {
                message: "something else entirely".to_owned()
            }
        );
    }

    #[test]
    fn fatal_and_transient_sets_partition_the_variants() {
        let all = [
            TransportError::InterfaceLost,
            TransportError::SocketClosed,
            TransportError::PermissionLost,
            TransportError::FatalIo {
                message: "m".to_owned(),
            },
            TransportError::SendBufferFull,
            TransportError::WouldBlock,
            TransportError::Interrupted,
            TransportError::SendTimedOut,
        ];
        let fatal = all.iter().filter(|e| e.is_fatal()).count();
        assert_eq!(fatal, 4, "exactly the four documented fatal variants");
    }

    #[test]
    fn display_messages_are_single_lines() {
        // Messages surface in scan summaries; they must stay one line and
        // carry the essential fact.
        for err in [
            TransportError::InterfaceLost,
            TransportError::SendBufferFull,
            TransportError::FatalIo {
                message: "unwrapped errno 42".to_owned(),
            },
        ] {
            let text = err.to_string();
            assert!(!text.contains('\n'));
            assert!(!text.is_empty());
        }
    }
}
