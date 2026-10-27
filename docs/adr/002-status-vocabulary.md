# ADR-002: Status vocabulary (Recent / Idle)

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-002 — Status vocabulary — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text.

> The Linux kernel uses `STALE` for a different concept.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> To avoid confusion in code, docs and UI we use **Recent** and **Idle**. "Stale" MUST NOT appear in our code identifiers or UI. Property-level absence uses `Unknown` / `Unavailable` (§5.2).

## Consequences (positive, negative, follow-ups)

- Property-level absence uses `Unknown` / `Unavailable` (§5.2) (plan.md §4).
- (T-001 note) The controlled vocabulary derived from this decision is enforced by the review check that greps for banned wording (plan.md §5.4, §11.7).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
