# ADR-001: Product naming

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Owner — name confirmed in plan v1.1.0 (open item O-1 resolved; plan.md §20, §22)

## Context

Source: plan.md v1.1.0 §4 (ADR-001 — Naming — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001 (task card §5.4), not plan text.

> The source brief mixes `osza-tools` and `veex-tools`.

## Options considered

See plan.md §4 — the contending names recorded there are `osza-tools` and `veex-tools` (source brief); the choice was confirmed by the Owner in plan v1.1.0 (plan.md §22, Changelog; open item O-1 resolved).

## Decision

> Names: ecosystem `osza-tools`; crate and binary `osza-netmon`; display name "osza Network Monitor". The name MUST live in exactly one place in code (`pub const APP_NAME`/`DISPLAY_NAME`) plus `Cargo.toml`, so a rename is a one-commit change. The Owner confirmed the name and created the repository at https://github.com/osza-tools/osza-netmon.

## Consequences (positive, negative, follow-ups)

- Rename cost (plan.md §4): "The name MUST live in exactly one place in code (`pub const APP_NAME`/`DISPLAY_NAME`) plus `Cargo.toml`, so a rename is a one-commit change."
- (T-001 cross-reference, task card §5.4 — rename-one-commit principle) Because the name lives in exactly one place in code plus `Cargo.toml`, a rename is a single-commit change. T-000 implemented this principle: `APP_NAME` / `DISPLAY_NAME` are the only name constants, defined in `src/lib.rs` (docs/reports/T-000/execution-01.md, §3).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports. The name constants have existed in `src/lib.rs` since T-000 (docs/reports/T-000/execution-01.md, §3).
