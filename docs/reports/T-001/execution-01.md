# Execution Report — T-001 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-10-28 · **Branch/commits:** `task/T-001-adr-records` — `18b6dcc`, `8e948c1`, plus this report · **Plan version:** 1.1.0 (repository copy, commit `cea93e4`)

**Pull request:** https://github.com/osza-tools/osza-netmon/pull/3 · **Green CI run:** https://github.com/osza-tools/osza-netmon/actions/runs/40555151453 (commit `8e948c1`)

## 1. Summary (≤ 5 lines)

All 16 ADRs transcribed into `docs/adr/` from plan.md v1.1.0 §4 using the Appendix G template, with statuses exactly per §4 (the card §5.2 status list matches superseded plan v1.0.0 for ADR-001/014/016 — resolved by plan §0.2 precedence and raised as PQ-1), plus a master `index.md` and a one-line `AGENTS.md` decision-log reference. All gates pass locally and on the PR. Enforcement is re-proven on the throwaway branch `task/T-001-enforcement-proof` (PR #4, never merged): four isolated violations — `unsafe`, `.unwrap()`, `println!` in `src/lib.rs`, and a `.rs` file without an SPDX header — each rejected by its own red CI run. A mechanical fidelity check confirms every quoted sentence in the ADRs appears verbatim in plan.md.

## 2. Acceptance criteria

| AC | Status | Evidence (test name, command, file) |
|---|---|---|
| All 16 ADR files exist in `docs/adr/` with correct `NNNN-title.md` naming | Met | `find docs/adr -name "*.md" | sort` in §4: exactly the 16 names from card §3, plus `index.md` and the pre-existing `README.md`. |
| Every ADR uses the exact template from Appendix G | Met | Each file: `# ADR-nnn: <title>` + Status / Date / Deciding-task bullets + Context / Options considered / Decision / Consequences / Evidence sections. Rendering nuance (Appendix G one-line metadata vs card §5.1 three bullets) in deviation 2. |
| Each ADR's status matches §4 of plan.md v1.1.0 | Met | Summary table in §4; statuses taken from v1.1.0 §4. Card §5.2's divergent list (ADR-001 "Provisional", ADR-014/016 "Open") matches plan v1.0.0 — PQ-1. |
| All Pending/Open ADRs correctly name their deciding task or owner | Met | ADR-009/010/011 "Pending — decided by T-105"; ADR-015 "Pending — decided by T-203"; ADR-014 "Owner — confirmed GPL-3.0 in T-000 report" (card §5.3 wording). |
| `index.md` lists all 16 ADRs with correct statuses, titles, and file links | Met | `cat docs/adr/index.md` in §4 (16 rows, relative links verified by the file list). |
| No ADR modifies or rewrites decision content from plan.md §4 | Met | Mechanical check (§4): 47 blockquoted lines / 87 quoted sentences across the 16 files, every one found verbatim in plan.md; non-plan text is confined to clearly marked "(T-001 …)" lines and template fallbacks. |
| `AGENTS.md` references the ADR directory | Met | One line added after the Authority line (see §3); nothing else changed in the file. |
| All engineering gates pass | Met | §4: fmt, clippy `-D warnings`, test (7/7), doc, audit, deny all exit 0 locally; CI run 40555151453 green on the PR. |

## 3. What changed

On `task/T-001-adr-records` (base: `main` at `cea93e4`):

- `18b6dcc` — `docs/adr/001…016-*.md`: 16 ADR files, one per decision in plan.md v1.1.0 §4, transcribed verbatim (quotations) with Appendix G structure, correct statuses, and the card §5.4 cross-references (ADR-009/010/011 ↔ each other ↔ T-105; ADR-005 → ADR-013; ADR-001 rename-one-commit principle).
- `8e948c1` — `docs/adr/index.md` (master index: 16 rows with number, title, status, link; status vocabulary; PQ-1 note) and `AGENTS.md` (+1 line: "Decision log: docs/adr/ …").
- report commit — `docs/reports/T-001/execution-01.md` (this file).

NOT part of the deliverable (throwaway, never merged): branch `task/T-001-enforcement-proof` (PR #4) with six commits — four violations and two isolation fixups — described in §4.

No production code, `Cargo.toml`, lockfile, workflow, or any other non-docs file was touched on the deliverable branch.

## 4. Verification results

Card §9 commands, executed 2026-10-28 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; fresh session — the toolchain, cargo-audit 0.22.2 and cargo-deny 0.20.2 were reinstalled at the same pins as CI, release tarballs SHA-256-verified):

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.56s
[exit 0]

$ cargo test --all-features           # run with --locked (deviation 3)
   Compiling/running 3 suites (lib, bin, doc-tests)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[exit 0 — Cargo.lock byte-identical afterwards]

$ cargo doc --no-deps 2>&1 | tail -30
 Documenting osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.14s
    Generated /home/z/my-project/osza-netmon/target/doc/osza_netmon/index.html
[exit 0; CI variant with RUSTDOCFLAGS="-D warnings": also exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1380 security advisories
    Scanning Cargo.lock for vulnerabilities (188 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings]

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — known benign warnings: license-not-encountered (BSD-2-Clause, BSD-3-Clause, ISC), multiple-versions (syn) — warnings by policy]

$ find docs/adr -name "*.md" | sort
docs/adr/001-product-naming.md
docs/adr/002-status-vocabulary.md
docs/adr/003-hostname-resolution-policy.md
docs/adr/004-authorization-notice-policy.md
docs/adr/005-privilege-model.md
docs/adr/006-single-package-repository.md
docs/adr/007-aging-model.md
docs/adr/008-device-identity-shared-mac.md
docs/adr/009-discovery-transport-library.md
docs/adr/010-neighbor-table-source.md
docs/adr/011-probe-strategy.md
docs/adr/012-concurrency-model.md
docs/adr/013-persistence-model.md
docs/adr/014-project-license.md
docs/adr/015-dns-ptr-client.md
docs/adr/016-ci-provider.md
docs/adr/README.md
docs/adr/index.md
[18 files: 16 ADRs + index + pre-existing README]
```

**Mechanical fidelity check** (script: sentence-level comparison of every blockquoted line in the 16 ADR files against plan.md; see §6 for the rationale):

```text
$ python3 adr_fidelity_check.py
Checked 16 ADR files; 47 blockquoted lines, 87 quoted sentences extracted.
PASS: every quoted sentence appears verbatim in plan.md.
```

**ADR summary table** (card §9 requirement):

| ADR | File | Status (plan.md v1.1.0 §4) | Faithful to §4 |
|---|---|---|---|
| 001 | 001-product-naming.md | Accepted | Yes — verbatim quotes, mechanical check |
| 002 | 002-status-vocabulary.md | Accepted | Yes — verbatim quotes, mechanical check |
| 003 | 003-hostname-resolution-policy.md | Accepted | Yes — verbatim quotes, mechanical check |
| 004 | 004-authorization-notice-policy.md | Accepted | Yes — verbatim quotes, mechanical check |
| 005 | 005-privilege-model.md | Accepted (mechanism details Pending T-104/T-105) | Yes — verbatim quotes (items 1–8), mechanical check |
| 006 | 006-single-package-repository.md | Accepted | Yes — verbatim quotes, mechanical check |
| 007 | 007-aging-model.md | Accepted | Yes — verbatim quotes, mechanical check |
| 008 | 008-device-identity-shared-mac.md | Accepted | Yes — verbatim quotes, mechanical check |
| 009 | 009-discovery-transport-library.md | Pending (T-105) | Yes — candidates/criteria/trait verbatim |
| 010 | 010-neighbor-table-source.md | Pending (T-105) | Yes — options and T-102/T-105 path verbatim |
| 011 | 011-probe-strategy.md | Pending (T-105), defaults below | Yes — provisional defaults verbatim |
| 012 | 012-concurrency-model.md | Accepted | Yes — verbatim quote, mechanical check |
| 013 | 013-persistence-model.md | Accepted | Yes — verbatim quote, mechanical check |
| 014 | 014-project-license.md | Accepted (variant to confirm, O-7) | Yes — all four consequence bullets verbatim |
| 015 | 015-dns-ptr-client.md | Pending (T-203) | Yes — §4 records only the table row; candidates cited from §9.2, task text from §13 |
| 016 | 016-ci-provider.md | Accepted | Yes — verbatim quotes, mechanical check |

**Enforcement proof — CI gates reject violations mechanically.** The task message emphasizes this ("demonstrate with failed examples that CI gates actually reject any unsafe, unwrap, println! code, or files without a license header"). Although the T-001 card's acceptance criteria do not list it (T-000 already proved it), the proof was re-run on top of the T-001 changes to show that the documentation task weakened nothing. Methodology mirrors T-000: a throwaway branch `task/T-001-enforcement-proof` based on `task/T-001-adr-records`, one violation per commit, pushed one at a time, each with its own red CI run; PR #4 (https://github.com/osza-tools/osza-netmon/pull/4) targets the task branch so the diff contains only the violations, and is **never merged** ("DO NOT MERGE").

| Violation | Commit | CI run | Failing CI step(s) | Local gate output (same content) |
|---|---|---|---|---|
| (a) `unsafe {}` block in `src/lib.rs` | `129233f` | [40555610827](https://github.com/osza-tools/osza-netmon/actions/runs/40555610827) | `cargo clippy --all-targets --all-features -- -D warnings` **and** MSRV `cargo build --locked` (unsafe_code = forbid is a rustc lint, so the build itself fails) | `error: usage of an \`unsafe\` block` (clippy exit 101) |
| (b) `.unwrap()` in non-test code | `f16e6f2` | [40555981685](https://github.com/osza-tools/osza-netmon/actions/runs/40555981685) | clippy step only — fmt, MSRV build, audit, deny all green | `error: used \`unwrap()\` on an \`Option\` value` (exit 101) |
| (c) `println!` in `src/lib.rs` | `dc732b1` | [40556293035](https://github.com/osza-tools/osza-netmon/actions/runs/40556293035) | clippy step only | `error: use of \`println!\`` (exit 101) |
| (d) `src/unlicensed.rs` without SPDX header (outside the module tree, so everything else compiles) | `4ed185a` | [40556612352](https://github.com/osza-tools/osza-netmon/actions/runs/40556612352) | SPDX header check only — fmt, clippy, test, doc, MSRV, audit, deny all green | `missing SPDX header: ./src/unlicensed.rs` (exit 1) |

Two proof-tooling runs are reported for completeness (same pattern as T-000's deviation 6): `f3ba6c4` (violation (a) with a doubled blank line) was rejected by the **fmt** gate before clippy ran — incidental evidence that fmt rejects whitespace-level violations — and `98d1a15` (violations (a)+(b) momentarily stacked) was auto-cancelled by the workflow's concurrency policy when the isolating fixup was pushed. Each violation above is isolated on its own commit with a dedicated red run; no shared history was rewritten.

Local enforcement demonstration (each violation applied to a clean tree, gate run, tree restored — final `git status --short` empty):

```text
(a) unsafe {}            → clippy: error: usage of an `unsafe` block … exit 101
(b) .unwrap() (non-test) → clippy: error: used `unwrap()` on an `Option` value … exit 101
(c) println! in lib.rs   → clippy: error: use of `println!` … exit 101
(d) src/unlicensed.rs    → SPDX check: missing SPDX header: ./src/unlicensed.rs … exit 1
```

**CI on the PR** (fresh checkout, run [40555151453](https://github.com/osza-tools/osza-netmon/actions/runs/40555151453), commit `8e948c1`, conclusion **success**): all three jobs green (fmt/clippy/test/doc/SPDX; audit/deny; MSRV build).

`cat docs/adr/index.md`:

```markdown
# ADR Index — osza-netmon

Architecture Decision Records for `osza-netmon`, transcribed from `plan.md` v1.1.0 §4 (Decision Log) by task T-001, using the ADR template from `plan.md` Appendix G. `plan.md` §4 remains the single source of truth; these files reproduce it faithfully and must stay consistent with it at all times.

Status vocabulary (plan.md §4): **Accepted** · **Provisional** (accepted, owner confirmation pending) · **Pending** (decided by evidence in a named task) · **Open** (owner decision) · **Superseded**.

| ADR | Title | Status | File |
|---|---|---|---|
| 001 | Product naming | Accepted | 001-product-naming.md |
| 002 | Status vocabulary (Recent / Idle) | Accepted | 002-status-vocabulary.md |
| 003 | Hostname resolution policy | Accepted | 003-hostname-resolution-policy.md |
| 004 | Authorization notice policy | Accepted | 004-authorization-notice-policy.md |
| 005 | Privilege model | Accepted (mechanism details Pending T-104/T-105) | 005-privilege-model.md |
| 006 | Single-package repository (lib + bin) | Accepted | 006-single-package-repository.md |
| 007 | Aging model (scan-cycle based) | Accepted | 007-aging-model.md |
| 008 | Device identity and shared-MAC handling | Accepted | 008-device-identity-shared-mac.md |
| 009 | Discovery transport library | Pending (T-105) | 009-discovery-transport-library.md |
| 010 | Neighbor-table source (`/proc/net/arp` vs netlink) | Pending (T-105) | 010-neighbor-table-source.md |
| 011 | Probe strategy (passes, rate, sender IP, unicast refresh) | Pending (T-105), provisional defaults | 011-probe-strategy.md |
| 012 | Concurrency: std threads, no async runtime | Accepted | 012-concurrency-model.md |
| 013 | Persistence: none, except the notice acknowledgment | Accepted | 013-persistence-model.md |
| 014 | Project license | Accepted (variant to confirm, O-7) | 014-project-license.md |
| 015 | DNS PTR client implementation | Pending (T-203) | 015-dns-ptr-client.md |
| 016 | CI provider: GitHub Actions | Accepted | 016-ci-provider.md |

Notes:

- All ADRs carry the transcription date 2026-10-28 (task T-001).
- Statuses are exactly those of `plan.md` v1.1.0 §4. Task card T-001 §5.2 listed three statuses that match the superseded plan v1.0.0 instead (ADR-001 "Provisional", ADR-014 "Open", ADR-016 "Open"); per `plan.md` §0.2 precedence (plan > task card) and the card's own rule "Every ADR's status must exactly match §4 of `plan.md`", the v1.1.0 statuses above are authoritative. See `docs/reports/T-001/execution-01.md`, Plan Question PQ-1.
- Pending decisions: ADR-009/010/011 are decided together by T-105; ADR-015 is decided by T-203; the ADR-005 capability-library mechanism is chosen by T-104; the ADR-014 SPDX variant remains open item O-7 (plan.md §20).
```

## 5. Deviations from the task card

1. **ADR statuses follow plan.md v1.1.0 §4, not the card §5.2 list.** The card's §5.2 status list matches the superseded plan v1.0.0 for ADR-001 ("Provisional"), ADR-014 ("Open") and ADR-016 ("Open") — verified against `git show 84c3d52:plan.md`. Plan v1.1.0 §4 lists all three as Accepted (changelog v1.1.0: "name confirmed (ADR-001), GPL-3.0 (ADR-014), GitHub Actions (ADR-016)"; open items O-1/O-3 resolved). Resolution: the card's own primary rule ("Every ADR's status must exactly match §4 of `plan.md`") plus plan §0.2 precedence (plan > task card). Raised as PQ-1.
2. **Template metadata rendering.** plan.md Appendix G places Date and "Deciding task / owner" on one bullet line; card §5.1 (quoting the template "applied exactly") renders them as two bullets. The card's rendering was used; the fields and the six sections are identical to Appendix G. No ADR is Superseded, so the "Superseded by ADR-xxx" variant is unused.
3. **`cargo test` / `cargo doc` run with `--locked`.** The card §9 commands omit it; CI and T-000 use it. `thiserror` is a caret requirement, so an unlocked resolve could rewrite the committed `Cargo.lock`; `--locked` protects it (verified byte-identical after the run).
4. **`cargo fmt --check` runs without `--locked`.** cargo-fmt rejects the flag (performs no dependency resolution) — same as T-000 deviation 3.
5. **No task-card copy at `docs/tasks/T-001.md`.** The T-001 card's deliverables (§6) do not list one (T-000's card did). Out-of-scope discipline; suggested as a follow-up if the Manager wants card copies for every task.
6. **Decider field for plan-time decisions.** Card §5.3's example format anticipates a task ID or "Owner". ADR-002…008, 012, 013 were decided at plan-authoring time ("the Manager's assessment", plan.md §22 Changelog v1.0.0), so their Deciding task / owner reads "Manager — plan.md v1.0.0 §4 (plan status: approved for execution)", with citation.
7. **Enforcement proof performed beyond the card's acceptance criteria**, because the task message emphasizes it; kept strictly off the deliverable branch (throwaway branch, never merged) to respect the documentation-only scope.

## 6. Decisions and assumptions

**Decisions:**

- **Status resolution (see PQ-1):** plan.md v1.1.0 §4 is authoritative for all 16 statuses. ADR-014 keeps §4's exact status string "Accepted (variant to confirm, O-7)" and the card §5.3 decider "Owner — confirmed GPL-3.0 in T-000 report"; the T-000 report's LICENSE/SPDX evidence is linked in its Evidence section.
- **Transcription convention:** plan §4 text appears as block quotations (verbatim, original emphasis and list structure); every non-plan line is either a template fallback ("See plan.md §4 — options were evaluated during …", "To be produced by T-…", "See plan.md §4 and future reports") or explicitly marked "(T-001 …)". Each Context section opens with a one-line provenance note stating this convention. Where §4 states no consequences, the Consequences section says so instead of inventing any.
- **Section placement:** §4 content is distributed across Context / Options considered / Decision / Consequences without rewording (e.g., ADR-005's items 7–8 → Options considered; item 6 → Consequences; ADR-007's age-floor and read-only sentences → Consequences). The fidelity checker therefore works at sentence granularity: a quoted line may join plan sentences that §4 kept contiguous but the template separates. All 87 quoted sentences match plan.md verbatim.
- **ADR-015 (no §4 prose block):** the file reproduces the §4 table row, cites the §9.2 candidates (`simple-dns` / `hickory-proto`) and the §13 T-203 entry, and states plainly that §4 records no decision text beyond the row.
- **ADR-009/010/011 (shared §4 block):** each file quotes only its own portion and carries the card §5.4 cross-references naming the other two ADRs and T-105.
- **Local environment:** fresh session — rustup + pinned 1.99.1 toolchain (rustfmt, clippy) reinstalled; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from the same official release tarballs as CI with the same SHA-256 verification. Local and CI tool versions match.
- **Enforcement-proof methodology:** throwaway branch based on the task branch (not `main`), PR base = `task/T-001-adr-records` so the diff shows only violations; violations pushed one at a time with polling between pushes (the concurrency policy would otherwise cancel an in-flight run); two fixup commits isolate violations (a) and (b) after proof-tooling formatting noise, mirroring T-000's accepted deviation 6. Each violation also pre-verified locally (fmt clean + target-lint failure) before pushing.

**Assumptions** (per plan §0.2, written down):

- The `plan.md` at the repository root (commit `cea93e4`, "chore: plan.md (v1.1.0)") is the authoritative plan; the card's "Plan version: 1.1.0" refers to it.
- "The repository above" in ADR-016 §4 means https://github.com/osza-tools/osza-netmon (stated in the ADR's Context).
- The task message's enforcement-proof emphasis applies to T-001 as a re-verification that the gates still reject violations after the documentation change (the card itself does not list it); it was executed off-branch rather than skipped.

## 7. Dependencies

None. Documentation-only task; `Cargo.toml`, `Cargo.lock` and the workflow files are untouched on the deliverable branch.

## 8. Plan Questions

- **PQ-1** · Context: task card T-001 §5.2 lists ADR-001 as "Provisional" and ADR-014/ADR-016 as "Open", while §5.2's own first sentence and acceptance criteria require statuses to "exactly match §4 of `plan.md`" · What the plan says: plan.md v1.1.0 §4 lists ADR-001 "Accepted" (Owner confirmed the name and created the repository; §22 Changelog v1.1.0 "name confirmed (ADR-001)"; open item O-1 resolved), ADR-014 "Accepted (variant to confirm, O-7)" and ADR-016 "Accepted" (changelog: "GitHub Actions (ADR-016)"; O-3 resolved); §0.2 gives the plan precedence over the task card · Ambiguity/conflict: the card's status list is byte-for-byte the superseded plan v1.0.0 §4 table (verified: `git show 84c3d52:plan.md` — v1.0.0 lists 001 "Provisional", 014 "Open (owner)", 016 "Open (owner)") · Options with consequences: (1) follow plan v1.1.0 §4 — satisfies the card's primary rule and §0.2 precedence; applied; (2) follow the card's §5.2 list — would contradict both the card's primary rule and the current plan, and would mark owner-confirmed decisions as open; (3) stop for a corrected card — stalls Phase 0 documentation on a discrepancy the plan already resolves · Executor's recommendation: option 1 (applied); the Manager should confirm and, if the §5.2 list was intentional, issue a corrected card or a plan bump, after which the three ADR statuses and the index would be updated in one commit · Blocking? No — resolved by the plan's own precedence rule; flagged for confirmation.

## 9. Security and privacy notes

- **No production code modified on the deliverable branch** — docs and one `AGENTS.md` line only; the diff of PR #3 is entirely `.md` files. The working tree was verified clean (`git status --short` empty) after each local enforcement demonstration, and `Cargo.lock` is byte-identical.
- **Enforcement-proof branch:** the violations exist only on `task/T-001-enforcement-proof` (PR #4, "DO NOT MERGE", never merged; ends in violation (d) by design, like T-000's PR #2). The gates rejected every one of them — the rules are enforced automatically, not by convention.
- **Untrusted inputs:** none handled; the task touches no code paths, no network beyond the GitHub API (push, PR creation, run polling), and no real MAC addresses, hostnames, or network details appear in any added file.
- **Secrets:** the GitHub token used for pushing and PR creation exists only in the sandbox environment and is present in no committed file, log, or report (command output redacted). It was transmitted in plaintext in the task message — rotation recommended (§11).

## 10. Known issues and limitations

- PR #3 receives a new CI run when this report commit is pushed; the green run recorded above (40555151453) is for commit `8e948c1`. The final head's run is expected green (docs-only diff) and should be checked at review time.
- The proof branch's stacked commit `98d1a15` was auto-cancelled by the concurrency policy; its evidence value is subsumed by the isolated run `40555981685`.
- `cargo deny check` emits the known benign warnings (license-not-encountered for unused allowlist entries; multiple-versions for `syn`) — warnings by policy, do not fail the gate (unchanged since T-000).
- ADR-015 has no §4 prose block in plan.md; if the Manager later adds one, the file (currently citing §9.2/§13) should be updated to quote it.
- `docs/adr/README.md` (created by T-000) already describes the directory correctly and was left untouched.

## 11. Suggested follow-ups

1. Manager: resolve PQ-1 — confirm that plan v1.1.0 §4 statuses stand (as transcribed) or issue a corrected T-001 card / plan bump; the ADR files and index would then be updated in one commit if needed.
2. Owner: rotate the GitHub token used for this task — it traveled in plaintext in the task message (repeat of the T-000 recommendation).
3. When T-104, T-105 and T-203 decide the Pending ADRs (005 mechanism, 009/010/011, 015), update the affected ADR files and `index.md` in those tasks so statuses and decision text stay consistent with the plan's Decision Log (the index commits to this).
4. Consider adding the task card copy convention (`docs/tasks/T-xxx.md`) to the card template if every task's card should be archived in-repo, as T-000's was.
5. Consider a CI docs-link check for the relative links in `docs/adr/index.md` in a future task (out of T-001 scope; links verified manually here via the file listing).
