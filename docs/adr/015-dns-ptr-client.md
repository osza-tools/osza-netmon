# ADR-015: DNS PTR client implementation

- **Status:** Pending (T-203)
- **Date:** 2026-10-28
- **Deciding task / owner:** Pending — decided by T-203

## Context

Source: plan.md v1.1.0 §4 (ADR-015 — DNS PTR client implementation — Pending (T-203)), transcribed by task T-001. Prose marked as a quotation is verbatim plan text; lines marked "(T-001 …)" are cross-references or notes added by task T-001, not plan text. Plan.md §4 records this decision only as a Decision Log table row; no dedicated prose block exists there.

(T-001 note) Related plan context: the hostname-resolution policy that the client must implement is ADR-003 (Accepted); plan.md §13 defines the deciding task: "T-203 Hostname resolver · M · Implements: FR-EN-03, ADR-003, ADR-015 — Resolver-selection logic (resolv.conf + systemd-resolved file, subnet rule), PTR query/response via the DNS crate chosen under §9.2, worker thread with bounded queue, timeout/retry/backoff, validation into `Hostname`, `--no-hostnames`."

## Options considered

Candidates recorded in the plan.md §9.2 candidates table ("decision by ADR in the named task"):

> DNS wire format: `simple-dns` / `hickory-proto` (T-203)

— to be evaluated against §9.2 in the report; the Manager approves.

## Decision

Pending — decided by T-203. Plan.md §4 records no decision text beyond the table row ("DNS PTR client implementation — Pending (T-203)").

## Consequences (positive, negative, follow-ups)

- The DNS client crate is chosen by T-203 under the plan.md §9.2 criteria, with Manager approval.
- (T-001 cross-reference) ADR-003 (Hostname resolution policy) fixes the policy the client implements: PTR queries sent directly to an eligible local resolver, never through the libc/NSS resolver.
- No further consequences are recorded in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

To be produced by T-203.
