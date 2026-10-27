# ADR-006: Single-package repository (lib + bin)

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-006 — Repository structure — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. No separate background is stated in plan.md §4.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> One Cargo package with `lib.rs` + `main.rs`. No workspace and no shared crate with other osza tools until a second tool needs the same code.

## Consequences (positive, negative, follow-ups)

- Dev-only tools live in `examples/`; fuzz targets in a separate `fuzz/` package excluded from builds. (plan.md §4)
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports. T-000 implemented the single package (`src/lib.rs` + `src/main.rs`, no workspace; docs/reports/T-000/execution-01.md, §3).
