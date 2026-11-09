# ADR-018: Signal handling (SIGTERM/SIGHUP) for the terminal lifecycle

- **Status:** Accepted (decided by T-301, 2026-11-10; ratified — plan v1.11.0)
- **Date:** 2026-11-10 · **Deciding task / owner:** T-301 (Executor decision per the task card §5.3; Manager approval in review)

## Context

Task card T-301 §5.3 (plan §8.8) requires: on SIGTERM/SIGHUP the application
quits through its normal quit path — the signal bridge sends the same
`AppEvent` the Ctrl+C key produces, so the ordinary T-205 runtime shutdown
runs and the terminal is restored — and requires this ADR recording the
library decision under the §9 dependency policy. The pre-authorized
`Cargo.toml`/`Cargo.lock` changes were exactly: (a) `signal-hook =
"=<locked version>"` as a direct exact pin, or (b) adding feature flags to
the existing pinned `nix`. No other change was allowed without a Plan
Question. A std-only handler is not an option: installing one requires
`signal(2)`/`sigaction(2)` through FFI, i.e. `unsafe`, which §14.3.4
prohibits.

The evaluation criteria of plan §9.2, copied in as the card mandates:

1. Necessity: what is the smallest alternative (std, 30 lines of our code)?
2. Maintenance: last release date, open advisories (`cargo audit`), issue
   health.
3. License compatible with `deny.toml` allowlist
   (MIT/Apache-2.0/BSD/ISC/Unicode).
4. `unsafe` footprint and what it wraps.
5. Transitive dependency count and build-time cost; no async runtime pulled
   in.
6. MSRV compatible with our pinned toolchain.
7. Works with our constraints: no network at runtime, no build scripts that
   fetch data.

## Options considered

**Option A — `signal-hook` 0.3.18 as a direct exact pin (chosen).**
`signal-hook` is *already in `Cargo.lock`*: the pinned crossterm 0.29.0
(ratatui 0.30.2's backend, the only terminal stack the plan allows) depends
on `signal-hook` for its own SIGWINCH handling — verified in the locked
source (`crossterm-0.29.0/src/event/source/unix/mio.rs`:
`signal_hook_mio::v1_0::Signals::new([signal_hook::consts::SIGWINCH])`).
The locked version is 0.3.18 and crossterm consumes it with default
features (`channel`, `iterator`), so taking it as a direct dependency with
the same default features adds **zero new crates to the tree and compiles
no code that was not already compiled** — the entire `Cargo.lock` diff of
this task is the single edge `"signal-hook",` under `osza-netmon`'s
dependency list (verified; the report §7 pastes it).

**Option B — `nix` `signalfd`.** `nix` 0.31.3 is approved and pinned, but
only with the `net` and `process` features; `signalfd` lives behind the
`signal` feature, so this option requires the card's alternative (b): a
feature-flag addition to the pinned `nix`. It would also not add a crate
(`libc` is already in the tree), but the integration is strictly more of
our own code: a signalfd created and registered nowhere (there is no
reactor), a readiness loop over the raw fd, signal-info parsing, and
close/reap handling — everything `signal-hook`'s `Signals` iterator already
provides safely. Since option A needs no feature change at all, B's only
remaining argument (fewer direct dependencies by one) does not survive the
§9.2.1 minimality test applied to *our* code.

**Option C — std-only handler.** Prohibited: installing a handler is
`unsafe` FFI (§14.3.4), and there is no `libc` dependency to build it on in
any case.

## Decision

`signal-hook = "=0.3.18"` — a direct, exact-pinned dependency (option A;
the card's pre-authorized change (a)). One small signal thread (the second
and last thread T-301 may add) waits on
`Signals::new([SIGTERM, SIGHUP])`'s blocking iterator and, per arriving
signal, delivers the quit intent through the `AppEventSender` with the
lifecycle-delivery policy (retry until delivered or stopped — the same
shape as the runtime forwarder's lifecycle events); the intent is exactly
the Ctrl+C key event, so the app core's ordinary quit path runs from any
screen or overlay and the §8.8 terminal restore follows. Shutdown is
bounded without any polling: `Handle::close()` wakes the blocked iterator,
so the thread joins immediately after the close (one in-flight retry
budget at worst).

## §9.2 evaluation (signal-hook 0.3.18)

1. **Necessity**: the alternative that avoids a new direct dependency is
   option B, which trades one crate-free direct edge for ~30+ lines of
   signalfd plumbing we would own and test; the std path is `unsafe` and
   prohibited. The direct pin of an already-locked crate is the smallest
   honest surface.
2. **Maintenance**: 0.3.18 is a long-stable release line (the crate has
   been maintained since 2019); `cargo audit` (task §7 gate) reports zero
   advisories for it.
3. **License**: Apache-2.0 OR MIT — inside the `deny.toml` allowlist
   (`cargo deny check` green, task §7).
4. **`unsafe` footprint**: `unsafe` exists inside `signal-hook-registry`
   (the `sigaction` wrappers — that is the crate's purpose); our code uses
   only the safe iterator API. `unsafe_code = "forbid"` holds for our
   package.
5. **Transitives**: none added — `signal-hook-registry` and `libc` were
   already in the lock (crossterm's own use); no async runtime, no build
   script.
6. **MSRV**: compatible (built and tested under the pinned 1.99.1 and the
   MSRV 1.89.0 gate, task §7).
7. **Constraints**: pure local signal delivery; no network, no data
   fetching, no runtime I/O beyond the self-pipe the kernel writes on
   signal arrival.

## Consequences (positive, negative, follow-ups)

- **Positive**: zero new crates (lock diff: one edge); a safe, purpose-built
  API; bounded close-woken shutdown with no polling and therefore no idle
  wake-ups from the signal thread at all (NFR-04); coexistence with
  crossterm's own SIGWINCH registration is by construction (separate
  registrations in the same registry — proven live by the pty resize test,
  where `stty`-driven `TIOCSWINSZ` reaches the app as a `Resize` event
  while SIGTERM/SIGHUP quit it).
- **Negative**: one more exact-pinned direct dependency to carry (the same
  maintenance shape as `ratatui`, `nix`, `pnet_datalink`, `caps`); a
  signal wakes one thread per delivery (negligible; only on actual
  signals).
- **Follow-ups**: none assigned. If a future task wants signal *numbers*
  or richer payloads (e.g. SIGUSR1 reload semantics), the
  `signal-hook`'s exfiltrator feature set already covers it without a new
  crate.

## Evidence

- The lock diff and the crossterm source citations above (task T-301
  execution report §7).
- The pty scenarios `restore_sigterm` and `restore_sighup`
  (`tests/pty/main.rs`): exit 0, raw mode and mouse capture restored after
  each signal — the acceptance evidence of task card §6 (d)/(e).
- The resize scenario: SIGWINCH and SIGTERM/SIGHUP registrations coexisting
  in one process, live.
