# ADR-005: Privilege model

- **Status:** Accepted (mechanism details Pending T-104/T-105)
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution); capability-library mechanism chosen by T-104 (Pending)

## Context

Source: plan.md v1.1.0 §4 (ADR-005 — Privilege model — Accepted (mechanism details Pending T-104/T-105)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. The §4 entry is a numbered model (items 1–8); the original numbering is preserved across the sections below.

## Options considered

> 7. Capability library candidates: `caps` or `capctl` (the latter's last release was March 2024). Chosen in T-104 under §9 criteria; `unsafe` stays forbidden in our own code.

> 8. Rejected: triggering ARP via UDP/TCP connects to every address (touches ports, unreliable, violates §2.3).

## Decision

> 1. The process runs as an unprivileged user. It is never setuid and never re-executes itself through `sudo`.
> 2. Before the TUI starts, it tries to open one `AF_PACKET` socket bound to the selected interface and `ETH_P_ARP`. This needs `CAP_NET_RAW`, granted to the binary by `setcap cap_net_raw+ep`.
> 3. After the socket is open, the process **drops its capabilities** (effective, permitted, inheritable, ambient) and sets `no_new_privs`, before it processes any untrusted input. Tests verify `CapEff`/`CapPrm` in `/proc/self/status` are zero afterwards.
> 4. If the socket cannot be opened (`EPERM`), the app starts in **read-only mode** (neighbor table only) with an actionable message — not an error exit.
> 5. If started with euid 0, the app warns once ("running as root is not required; use file capabilities") and still drops capabilities.

## Consequences (positive, negative, follow-ups)

- `docs/permissions.md` documents the trade-off: file capabilities allow any user who can execute the binary to open a raw socket; recommend restricting execution by group (`chgrp`/`chmod 750`). (plan.md §4, item 6)
- Follow-up: the capability library is chosen in T-104 under §9 criteria; `unsafe` stays forbidden in our own code (plan.md §4, item 7).
- (T-001 cross-reference, task card §5.4) ADR-013 (Persistence model): the process runs unprivileged per this ADR, and the only state it persists is the notice acknowledgment defined by ADR-004/ADR-013.
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
