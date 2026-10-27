# ADR-014: Project license

- **Status:** Accepted (variant to confirm, O-7)
- **Date:** 2026-10-28
- **Deciding task / owner:** Owner — confirmed GPL-3.0 in T-000 report

## Context

Source: plan.md v1.1.0 §4 (ADR-014 — License — Accepted (variant to confirm, O-7)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references or notes added by task T-001, not plan text.

> The Owner chose **GPL-3.0**.

## Options considered

The SPDX variant is open item O-7 (plan.md §20: `GPL-3.0-only` or `GPL-3.0-or-later`; default `GPL-3.0-only`). From plan.md §4:

> Until the Owner states otherwise (O-7) the SPDX identifier is `GPL-3.0-only` (the literal reading); `GPL-3.0-or-later` is the alternative.

## Decision

> The Owner chose **GPL-3.0**. Until the Owner states otherwise (O-7) the SPDX identifier is `GPL-3.0-only` (the literal reading); `GPL-3.0-or-later` is the alternative.

(T-001 note, task card §5.3) The Owner confirmed GPL-3.0 in the T-000 report; the variant applied since T-000 is `GPL-3.0-only` (see Evidence).

## Consequences (positive, negative, follow-ups)

> - The repository carries a verbatim `LICENSE` file (text from https://www.gnu.org/licenses/gpl-3.0.txt — never paraphrased or reproduced from memory), `license = "GPL-3.0-only"` in `Cargo.toml`, and every `.rs` file starts with `// SPDX-License-Identifier: GPL-3.0-only`. CI enforces the header.
> - The `deny.toml` license allowlist contains only licenses compatible with GPL-3.0 (for example MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0). Apache-2.0 is compatible with GPLv3. Any other license needs a Plan Question.
> - The IEEE-derived vendor data is data, not our code; its source, terms and attribution are recorded in `data/oui/SOURCE.md` (T-202).
> - `publish = false` stays in `Cargo.toml` until the Owner decides to publish on crates.io.

- Follow-up (plan.md §20, open item O-7): the SPDX variant (`GPL-3.0-only` vs `GPL-3.0-or-later`) remains open for the Owner to state; default applied since T-000: `GPL-3.0-only`.
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports. The Owner confirmed GPL-3.0 in the T-000 report (docs/reports/T-000/execution-01.md): verbatim `LICENSE` (35,149 bytes, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`), `license = "GPL-3.0-only"` in `Cargo.toml`, SPDX headers on every `.rs` file, enforced by CI.
