# ADR-012: Concurrency: std threads, no async runtime

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-012 — Concurrency: std threads, no async runtime — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records ADR-012/013 in one shared block.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> `std::thread` + bounded channels. No tokio or other async runtime in the MVP.

## Consequences (positive, negative, follow-ups)

- No further consequences are stated in plan.md §4.
- (T-001 note) Since T-000, `deny.toml` bans async-runtime crates, so the CI supply-chain gate mechanically excludes them from the dependency tree (docs/reports/T-000/execution-01.md, §9).

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
