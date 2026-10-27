# ADR-009: Discovery transport library

- **Status:** Pending (T-105)
- **Date:** 2026-10-28
- **Deciding task / owner:** Pending — decided by T-105

## Context

Source: plan.md v1.1.0 §4 (ADR-009 — Discovery transport library — Pending (T-105)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation".

## Options considered

> Candidates: `pnet_datalink` (its latest release, 0.35.0, dates from May 2024 — slow cadence; do not assume it), `nix` safe wrappers, `socket2`.

(T-001 note) Also recorded in the plan.md §9.2 candidates table ("decision by ADR in the named task"): transport: `pnet_datalink` / `nix` / `socket2` (T-105) — evaluate against §9.2 in the report; Manager approves.

## Decision

Pending — decided by T-105; no decision text exists yet in plan.md §4 beyond the candidates, the criteria pointer and the isolation constraint, both quoted here:

> Criteria in §9.2; also the transport is hidden behind the `ArpTransport` trait so replacing it costs one module.

## Consequences (positive, negative, follow-ups)

- The transport is hidden behind the `ArpTransport` trait so replacing it costs one module. (plan.md §4)
- Evaluation happens against the plan.md §9.2 criteria, with Manager approval (plan.md §4, §9.2).
- (T-001 cross-reference, task card §5.4) ADR-009, ADR-010 (Neighbor-table source) and ADR-011 (Probe strategy) are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

To be produced by T-105.
