// SPDX-License-Identifier: GPL-3.0-only

//! The SIGTERM/SIGHUP bridge (task T-301 §5.3; ADR-018).
//!
//! One small signal thread (the second and last thread this task may
//! add) waits on `signal-hook`'s [`Signals`] iterator for SIGTERM and
//! SIGHUP and quits through **the app's normal quit path**: it sends
//! the same event the Ctrl+C key produces
//! ([`AppEvent::Input(Key::CtrlC)`](crate::app::AppEvent::Input)) —
//! no new event variant exists, and the app core already quits from
//! every screen and overlay — so the ordinary runtime shutdown runs
//! and the terminal is restored (§5.6). The delivery mirrors the
//! runtime forwarder's *lifecycle* policy: a quit intent retries
//! until delivered or the stop flag is set (the main loop drains, so
//! this terminates); a full queue cannot wedge the exit.
//!
//! `signal-hook` 0.3.18 is the library ADR-018 chose: it is already
//! in `Cargo.lock` as the pinned crossterm's dependency (its SIGWINCH
//! source), so taking it as a direct exact-pinned dependency adds
//! zero crates to the tree and enables no feature that crossterm had
//! not already enabled (both use the default `iterator` set). See
//! `docs/adr/018-signal-handling.md` for the §9.2 evaluation against
//! the `nix` `signalfd` alternative.
//!
//! Shutdown is bounded without any polling: [`Handle::close`] wakes
//! the blocked iterator, so the thread joins immediately after the
//! close (plus one in-flight retry budget at worst) — no timer
//! wake-ups at all while idle (NFR-04).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use signal_hook::consts::SIGHUP;
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Handle;
use signal_hook::iterator::Signals;

use crate::app::AppEvent;
use crate::app::AppEventSender;
use crate::app::InputEvent;
use crate::app::Key;

/// The wait between two quit-delivery attempts (the forwarder's
/// `SEND_RETRY_WAIT`; the budget is "until delivered or stopped", the
/// lifecycle policy — the main loop drains, so this terminates).
const QUIT_RETRY_WAIT: Duration = Duration::from_millis(10);

/// The signal thread's name (pthread names are truncated to 15 bytes).
const SIGNAL_THREAD_NAME: &str = "osza-signals";

/// The quit event a signal produces: exactly what the Ctrl+C key
/// produces (§5.3 — the app's normal quit path, no new variant).
const QUIT_EVENT: AppEvent = AppEvent::Input(InputEvent::Key(Key::CtrlC));

/// The spawned signal thread plus the handle that shuts it down.
#[derive(Debug)]
pub struct SignalGuard {
    handle: Handle,
    thread: Option<JoinHandle<()>>,
}

/// Registers SIGTERM/SIGHUP and spawns the signal thread.
///
/// # Errors
/// The signal registration or the thread spawn failed (both
/// OOM/kernel-class); the assembly turns either into an honest error
/// exit before the terminal is touched.
pub fn spawn_signal_thread(
    sender: AppEventSender,
    stop: Arc<AtomicBool>,
) -> Result<SignalGuard, String> {
    let signals = Signals::new([SIGTERM, SIGHUP]).map_err(|error| error.to_string())?;
    let handle = signals.handle();
    let thread = thread::Builder::new()
        .name(SIGNAL_THREAD_NAME.to_owned())
        .spawn(move || signal_loop(signals, sender, stop))
        .map_err(|error| error.to_string())?;
    Ok(SignalGuard {
        handle,
        thread: Some(thread),
    })
}

/// The thread body: deliver one quit per arriving signal and stay in
/// the loop — a second signal while the first quit is in flight
/// re-requests it (idempotent), and the loop ends at shutdown when
/// [`Handle::close`] wakes the iterator.
fn signal_loop(mut signals: Signals, sender: AppEventSender, stop: Arc<AtomicBool>) {
    for _signal in signals.forever() {
        deliver_quit(&sender, &stop);
    }
}

/// Delivers the quit intent under the lifecycle policy (module docs):
/// retry until delivered or stopped.
fn deliver_quit(sender: &AppEventSender, stop: &AtomicBool) {
    let mut event = QUIT_EVENT;
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match sender.try_send(event) {
            Ok(()) => return,
            Err(TrySendError::Full(returned)) => {
                event = returned;
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
        thread::sleep(QUIT_RETRY_WAIT);
    }
}

impl SignalGuard {
    /// Bounded shutdown: close the iterator (wakes the blocked
    /// thread), then join. Idempotent — a second call finds the
    /// handle closed and the thread already taken.
    pub fn shutdown(&mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // The safety net for paths that never called shutdown
        // explicitly (a panic unwinding past the loop).
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::app::RecordingExecutor;
    use crate::app::Runtime;
    use crate::app::SessionParams;
    use crate::discovery::worker::CycleEvent;
    use crate::model::Clock;
    use crate::model::FakeClock;
    use std::sync::mpsc::sync_channel;

    /// A minimal real runtime: the signal thread's deliveries land in
    /// a real bounded queue and drive the real update loop.
    fn runtime_pair() -> (Runtime<RecordingExecutor>, AppEventSender) {
        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FakeClock::new());
        let vendor_db = Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        );
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            vendor_db,
            clock.as_ref(),
        )
        .expect("defaults are valid");
        let (dead_tx, dead_rx) = sync_channel::<CycleEvent>(1);
        drop(dead_tx);
        Runtime::new(state, RecordingExecutor::new(), dead_rx, clock)
    }

    #[test]
    fn shutdown_closes_and_joins_without_any_signal() {
        // The no-signal exit path: close() wakes the blocked iterator
        // and the join returns — bounded, no signal needed. Idempotent
        // (the second call finds the handle closed and the thread
        // already taken).
        let (mut runtime, sender) = runtime_pair();
        let stop = Arc::new(AtomicBool::new(false));
        let mut guard = spawn_signal_thread(sender, Arc::clone(&stop)).expect("spawn");
        thread::sleep(Duration::from_millis(50));
        let started = std::time::Instant::now();
        guard.shutdown();
        guard.shutdown();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "join must return promptly after close (took {elapsed:?})"
        );
        runtime.shutdown();
    }

    #[test]
    fn a_delivered_quit_is_exactly_the_ctrl_c_event() {
        // The quit intent is the same event the Ctrl+C key produces —
        // proven by delivering one through the real queue and
        // stepping the real runtime to a quit (the app core quits from
        // any screen; no new variant exists).
        let (mut runtime, sender) = runtime_pair();
        let stop = Arc::new(AtomicBool::new(false));
        let mut guard = spawn_signal_thread(sender.clone(), Arc::clone(&stop)).expect("spawn");
        deliver_quit(&sender, &stop);
        runtime.step(Duration::ZERO);
        assert!(runtime.state().quit(), "the signal quit path quits");
        guard.shutdown();
        runtime.shutdown();
    }

    #[test]
    fn stop_flag_interrupts_a_delivery_retry_loop() {
        // §8.3 discipline: a send that would block keeps checking the
        // stop flag — proven by wedging the queue full (the runtime
        // never steps, so nothing drains) and setting stop: the
        // delivery returns without hanging.
        let (mut runtime, sender) = runtime_pair();
        for _ in 0..crate::app::APP_EVENT_CAPACITY {
            let _ = sender.try_send(AppEvent::Tick);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                deliver_quit(&sender, &stop);
            })
        };
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        let _ = worker.join();
        // Free the queue so the runtime's own shutdown is not wedged.
        for _ in 0..4 {
            runtime.step(Duration::ZERO);
        }
        runtime.shutdown();
    }
}
