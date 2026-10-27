# ADR-003: Hostname resolution policy

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-003 — Hostname resolution policy — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text.

> Reverse DNS for local addresses can leak device information to external resolvers. Policy:

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment). (T-001 note: the DNS client library used to implement this policy is a separate, Pending decision — ADR-015, decided by T-203.)

## Decision

> 1. Hostname lookups use **PTR queries sent directly to an eligible local resolver**, never through the libc/NSS resolver (which may forward upstream or involve other name services).
> 2. Eligible resolver = a nameserver address from `/etc/resolv.conf` that lies **inside the selected subnet** (loopback stubs such as `127.0.0.53` are not eligible; if only a loopback stub is listed and `/run/systemd/resolve/resolv.conf` exists, use that file's entries under the same rule).
> 3. If no eligible resolver exists, hostname is `Unavailable (no local resolver)`. No fallback to other servers.
> 4. 1 s timeout, one retry, bounded queue, one lookup per (MAC, IP) pair, failed lookups retried no more than every 5 minutes.
> 5. `--no-hostnames` disables the feature. The help screen explains what is queried and where it goes.

## Consequences (positive, negative, follow-ups)

- Residual risk (a LAN resolver may forward PTR queries upstream) is documented in `docs/limitations.md` (plan.md §4, item 6).
- (T-001 note) `docs/limitations.md` is produced by task T-405 (plan.md §13).
- (T-001 cross-reference) The DNS client implementation is ADR-015 (Pending — decided by T-203); task T-203 implements this policy (plan.md §13: "T-203 Hostname resolver · Implements: FR-EN-03, ADR-003, ADR-015").
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
