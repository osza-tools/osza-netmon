# Execution Report — T-000 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-10-27 · **Branch/commits:** `task/T-000-bootstrap` — `d4cd53d`, `05aed22`, `82778a7`, `ba892fe`, plus this report · **Plan version:** 1.0.0 (the file present in the repository; the task card cites 1.1.0 — see PQ-1)

**Pull request:** https://github.com/osza-tools/osza-netmon/pull/1 · **Green CI run:** https://github.com/osza-tools/osza-netmon/actions/runs/40406852633 (commit `ba892fed`)

## 1. Summary (≤ 5 lines)

Repository bootstrap complete: Cargo package `osza-netmon` (lib + bin, edition 2024) with the toolchain pinned to Rust 1.99.1, MSRV 1.89 (determined and verified by a real build), `ratatui =0.30.2` and `thiserror` 2.0.21, committed `Cargo.lock`, GPL-3.0 `LICENSE`, and CI enforcing all §11.3 gates plus the SPDX header check — green on the PR. Enforcement is proven on the throwaway branch `task/T-000-enforcement-proof` (PR #2, never merged): four violation commits, each rejected by its own red CI run. Two Plan Questions were raised and resolved by Owner direction (plan-version mismatch; LICENSE sourcing).

## 2. Acceptance criteria

| AC | Status | Evidence |
|---|---|---|
| Fresh clone: `cargo build --locked` and `cargo test --locked` succeed | Met | CI run 40406852633 on a fresh checkout: job "MSRV build" runs `cargo build --locked`; job "fmt / clippy / test / doc / SPDX" runs `cargo test --locked --all-features`; both green. Local outputs in §4. |
| `--version` prints `osza-netmon <version>` exit 0; `--help` prints usage exit 0; unknown flag: one line to stderr, exit 2; non-UTF-8 argument does not panic | Met | §4 "Runtime behavior" outputs; tests `version_flags_are_recognized`, `help_flags_are_recognized`, `unknown_flag_is_an_error`, `non_utf8_argument_is_an_error_not_a_panic` (7/7 pass). |
| Enforcement proof: four throwaway commits each fail the gates — (a) `unsafe {}` block, (b) `.unwrap()` in non-test code, (c) `println!` in `lib.rs`, (d) `.rs` file without SPDX header | Met | Runs [40407372601](https://github.com/osza-tools/osza-netmon/actions/runs/40407372601) (a), [40407908432](https://github.com/osza-tools/osza-netmon/actions/runs/40407908432) (b), [40408236083](https://github.com/osza-tools/osza-netmon/actions/runs/40408236083) (c), [40408347764](https://github.com/osza-tools/osza-netmon/actions/runs/40408347764) (d); table in §4; branch `task/T-000-enforcement-proof` (PR #2, DO NOT MERGE, never merged). |
| fmt, clippy `-D warnings`, test, doc (warnings denied), audit, deny pass locally and in CI on the PR | Met | §4 outputs (all exit 0); CI run 40406852633, all gate steps green. |
| `deny.toml` implements §5.5, passes on the real dependency tree, allowlist contains only GPL-3.0-compatible licenses | Met | `cargo deny check` → `advisories ok, bans ok, licenses ok, sources ok`; license inventory in §6; strictness proof in §4 (removing `MIT` from the allow list makes the check fail with `error[rejected]`). |
| `LICENSE` byte-identical to the official GPL-3.0 text (URL and SHA-256 in the report); `license = "GPL-3.0-only"`; every `.rs` file has the SPDX header; CI enforces it | Met | §4 checksums (35,149 bytes, SHA-256 `3972dc97…36986`, source URL recorded; provenance deviation in §5/PQ-2); run 40408347764 proves CI rejects a missing header; local SPDX check: 2/2 files OK. |
| Toolchain pinned; MSRV determined and recorded; exact `ratatui` and `thiserror` versions recorded; `Cargo.lock` committed | Met | `rust-toolchain.toml` (1.99.1 + rustfmt + clippy); `Cargo.toml` `rust-version = "1.89"` with the method in §6; resolved versions in §6; `Cargo.lock` committed in `d4cd53d`. |
| CI uses SHA-pinned actions with `permissions: contents: read` and is green on the PR | Met | `.github/workflows/ci.yml` (both third-party actions pinned by full commit SHA with tag comments; workflow-level `permissions: contents: read`); run 40406852633 = success. |
| `AGENTS.md` matches plan Appendix F; `plan.md` at the root is identical to the supplied file (checksum recorded) | Met | `AGENTS.md` is a verbatim copy of the Appendix F block of the plan in the repository; `sha256sum plan.md` = `86333d9fb20c52e002aabc380c10e4d9a6a3ac1b00af96a337c7b853980e20d0` (85,150 bytes; zero-diff vs `main` — see §3). |
| `docs/` skeleton exists; `README.md` states pre-release status and license, no capability claims | Met | `docs/adr\|reports\|poc\|tasks/README.md`; `README.md` (pre-release notice, license, explicit non-completeness disclaimer). |
| No `unsafe`; no `println!`/`eprintln!` outside `main.rs`; no dependencies beyond `ratatui` and `thiserror` | Met | `unsafe_code = "forbid"`; print allows exist only in `src/main.rs` behind a justification comment; `[dependencies]` has exactly two entries; all of the above are machine-enforced by the CI gates and by the proof runs in §4. |

## 3. What changed

Four commits on `task/T-000-bootstrap` (base: `main`, which contains only `plan.md` v1.0.0 — untouched, zero-diff):

- `d4cd53d` — `LICENSE` (verbatim GPL-3.0), `.gitignore`, `rustfmt.toml`, `clippy.toml`, `rust-toolchain.toml` (1.99.1, rustfmt, clippy), `deny.toml`, `Cargo.toml` (lints, release profile, MSRV field), `Cargo.lock` (188 packages, lockfile v4), `README.md` stub, `AGENTS.md` (Appendix F verbatim)
- `05aed22` — `src/lib.rs`: `APP_NAME` / `DISPLAY_NAME` / `VERSION` constants (the only places the name appears, per ADR-001), `ArgError` (thiserror), `CliOutcome`, `classify_args` and 7 unit tests; `src/main.rs`: thin CLI with the narrowly scoped `#[allow(clippy::print_stdout)]` / `#[allow(clippy::print_stderr)]` on the three print helpers, justified by an explicit comment
- `82778a7` — docs skeleton (`docs/adr`, `docs/reports`, `docs/poc`, `docs/tasks`, one-line READMEs) and this task's card at `docs/tasks/T-000.md`
- `ba892fe` — `.github/workflows/ci.yml` (3 jobs / 8 gate steps, SHA-pinned actions, hash-verified tool installs, `permissions: contents: read`, concurrency) and `.github/dependabot.yml` (weekly: cargo, github-actions)
- report commit — `docs/reports/T-000/execution-01.md` (this file)

## 4. Verification results

Card §9 commands, executed 2026-10-27 with the pinned toolchain (rustc 1.99.1, x86_64-unknown-linux-gnu):

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s
[exit 0]

$ cargo test --locked --all-features
running 7 tests
test tests::no_arguments_prints_help ... ok
test tests::help_flags_are_recognized ... ok
test tests::only_the_first_argument_is_interpreted ... ok
test tests::non_utf8_argument_is_an_error_not_a_panic ... ok
test tests::program_name_is_ignored_even_if_it_looks_like_a_flag ... ok
test tests::unknown_flag_is_an_error ... ok
test tests::version_flags_are_recognized ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.21s
    Generated target/doc/osza_netmon/index.html
[exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1378 security advisories
    Scanning Cargo.lock for vulnerabilities (188 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings]

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
[exit 0]

$ cargo run --locked -- --version
osza-netmon 0.1.0
[exit 0]

$ cargo run --locked -- --help
osza Network Monitor 0.1.0 (pre-release)

Usage: osza-netmon [OPTIONS]

Options:
  -V, --version  Print version information and exit
  -h, --help     Print this help text and exit
[exit 0]

$ cargo run --locked -- --bogus
osza-netmon: unrecognized argument: --bogus
[exit 2]

$ cargo run --locked -- $'\xff\xfe\xfd'   # non-UTF-8 argument
osza-netmon: argument is not valid UTF-8
[exit 2 — no panic]

$ sha256sum plan.md LICENSE
86333d9fb20c52e002aabc380c10e4d9a6a3ac1b00af96a337c7b853980e20d0  plan.md
3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986  LICENSE
```

Additional task-specific verification:

- **MSRV build** — `rustup run 1.89.0 cargo build --locked` → `Finished dev profile [unoptimized + debuginfo] target(s)` (rustc 1.89.0, 2025-08-04). Run again after adding the `rust-version` field: pass.
- **clippy.toml option verification** — a temporary `#[cfg(test)]` probe exercising `unwrap()`, `expect()`, `panic!`, indexing, `println!`, `eprintln!` and `dbg!` inside test code was appended to `src/lib.rs`; `cargo clippy --locked --all-targets --all-features -- -D warnings` **passed** with all six options present, then the file was restored byte-exact and clippy re-verified green. Conclusion: all six option names (`allow-unwrap-in-tests`, `allow-expect-in-tests`, `allow-panic-in-tests`, `allow-indexing-slicing-in-tests`, `allow-print-in-tests`, `allow-dbg-in-tests`) are supported and honored by the pinned clippy 1.99.1. None is unsupported.
- **License allowlist strictness** — with `"MIT"` temporarily removed from `deny.toml`, `cargo deny check licenses` fails with repeated `error[rejected]: failed to satisfy license requirements`; restored, the check passes. The allow list is the gate, not a rubber stamp.
- **Local SPDX check** (mirror of the CI step): 2/2 `.rs` files carry the header.

**CI on the PR** (fresh checkout, run [40406852633](https://github.com/osza-tools/osza-netmon/actions/runs/40406852633), commit `ba892fed`, conclusion **success**):

| Job | Steps (all green) |
|---|---|
| fmt / clippy / test / doc / SPDX | Checkout · Install pinned toolchain · `cargo fmt --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all-features` · `cargo doc --no-deps` (warnings denied) · SPDX header check |
| cargo audit / cargo deny | Checkout · Install pinned toolchain · Install cargo-audit 0.22.2 · Install cargo-deny 0.20.2 · `cargo audit` · `cargo deny check` |
| MSRV build | Checkout · Read MSRV from Cargo.toml (1.89) · Install MSRV toolchain · `cargo build --locked` |

**Enforcement proof** (throwaway branch `task/T-000-enforcement-proof`, PR [#2](https://github.com/osza-tools/osza-netmon/pull/2), **never merged**, kept open for inspection):

| Violation | Commit | CI run | Failing CI step(s) | Local gate output (same commit) |
|---|---|---|---|---|
| (a) `unsafe {}` block in `src/lib.rs` | `1ad228d` | [40407372601](https://github.com/osza-tools/osza-netmon/actions/runs/40407372601) | clippy step **and** MSRV `cargo build --locked` (forbid is a rustc lint, so the build itself fails too) | `error: usage of an \`unsafe\` block` |
| (b) `.unwrap()` in non-test code | `502a1a7` | [40407908432](https://github.com/osza-tools/osza-netmon/actions/runs/40407908432) | clippy step only (fmt, test, doc, MSRV, audit, deny all green) | `error: used \`unwrap()\` on an \`Option\` value` |
| (c) `println!` in `src/lib.rs` | `b342502` | [40408236083](https://github.com/osza-tools/osza-netmon/actions/runs/40408236083) | clippy step only | `error: use of \`println!\`` |
| (d) `src/unlicensed.rs` without SPDX header (not in the module tree, so everything else compiles) | `e14817e` | [40408347764](https://github.com/osza-tools/osza-netmon/actions/runs/40408347764) | SPDX header check only — all seven other gate steps green | `missing SPDX header: ./src/unlicensed.rs` |

Two intermediate proof commits (`ff2b391`, `1af3cae`) were rejected by the **fmt** gate first (stray EOF whitespace / a doubled blank line introduced by the proof tooling; see deviation 6). Their red runs — [40407611907](https://github.com/osza-tools/osza-netmon/actions/runs/40407611907) and [40408075781](https://github.com/osza-tools/osza-netmon/actions/runs/40408075781) — incidentally demonstrate that `cargo fmt --check` rejects whitespace-level violations as well.

## 5. Deviations from the task card

1. **LICENSE source.** `https://www.gnu.org/licenses/gpl-3.0.txt` is unreachable from the execution sandbox (connection timeouts on ports 443 and 80; DNS resolves — an egress block, not a transient failure). Per the card §5.4 this is a blocking condition; the Owner was asked and directed the use of Debian's `/usr/share/common-licenses/GPL-3`, which is byte-identical to the canonical text: exactly 35,149 bytes, 674 lines, ends with a newline, and SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` — the widely published checksum of `gpl-3.0.txt`. The file was copied (not retyped) and `cmp`-verified; provenance is recorded here and in PQ-2.
2. **Plan version.** The card is issued against plan v1.1.0, but the repository contains v1.0.0 (single commit `84c3d52`), which has no §20 O-7 and calls the T-000 license field a placeholder. The Owner directed: the card is the operative spec; `plan.md` stays untouched. The mismatch is recorded as PQ-1 for the Manager to reconcile.
3. **`cargo fmt --check` runs without `--locked`.** `cargo fmt --check --locked` is rejected by cargo-fmt (`error: unexpected argument '--locked' found`); rustfmt performs no dependency resolution, so the flag is meaningless there. Every Cargo command that resolves dependencies (build, clippy, test, doc, run) uses `--locked`, locally and in CI.
4. **`std::env::args_os()` instead of `std::env::args()`.** `args()` panics on non-UTF-8 argv; the card's own requirement — "no panics for any argument input, including non-UTF-8" — mandates `args_os()` with an explicit `to_str()` check that maps to a typed error (exit 2). This stays within the "std only, no argument-parsing crate" constraint.
5. **No-arguments behavior (unspecified by the card).** With no arguments the binary prints the usage text and exits 0 — no product behavior; the interactive default that starts the TUI arrives with a later task. Documented in the `classify_args` doc comment and covered by the test `no_arguments_prints_help`.
6. **Two formatting fixup commits on the proof branch.** The proof tooling first produced commits (b-v1, c-v1) whose *formatting* failed the fmt gate (stray whitespace, a doubled blank line), masking the target lint. Follow-up commits (`502a1a7`, `b342502`) isolate the target failures; no shared history was rewritten (plan §14.3 rule 9). The initially-masking red runs are reported as additional fmt evidence in §4.
7. **Proof PR base.** The enforcement-proof PR targets `task/T-000-bootstrap` rather than `main`, so its diff contains only the violations. The branch is never merged either way.

## 6. Decisions and assumptions

**Resolved versions** (all recorded as required):

| Item | Value | How determined |
|---|---|---|
| Toolchain | Rust **1.99.1** (2026-10-13; rustc/cargo 1.99.1, rustup 1.29.2) | latest stable reported by rustup on 2026-10-27; pinned in `rust-toolchain.toml` with rustfmt + clippy |
| Edition | 2024 | latest stable edition supported by the pinned toolchain (stable since 1.85); implies an MSRV floor of 1.85 |
| MSRV | **1.89** | max `rust-version` declared across the 188 locked packages = 1.89.0 (`uuid` 1.29.0, a non-host-platform transitive dependency — treated conservatively as authoritative); verified with `rustup run 1.89.0 cargo build --locked` → Finished. Also covers the lockfile-v4 and `[lints]` floors. |
| ratatui | **0.30.2**, pinned exactly (`=0.30.2`) | latest stable on crates.io at task time (2026-06-19); exact pin per plan §9.1 |
| thiserror | **2.0.21** (requirement `"2"`) | latest stable (2026-09-23); exact resolution recorded in `Cargo.lock` |
| cargo-audit | **0.22.2** | latest stable (2026-06-05); installed from the official release with SHA-256 verification |
| cargo-deny | **0.20.2** | latest stable (2026-07-09); installed from the official release with SHA-256 verification |

**Decisions:**

- **CI tool installation (card §5.6 choice):** cargo-audit and cargo-deny are downloaded in the workflow from their *official* GitHub releases at pinned versions, and the SHA-256 of each tarball is verified before extraction (hashes embedded in `ci.yml`). Reasons: (1) cargo-audit's repository moved into the `rustsec/rustsec` monorepo (release tag `cargo-audit/v0.22.2`), which third-party installer actions may not track; (2) hash-verified pinned URLs are deterministic and auditable; (3) it adds no further third-party action to the supply chain (plan §7.1), keeping the workflow at two pinned actions; (4) no per-run compilation. Local verification used the same release artifacts (musl builds), so local and CI results match.
- **Actions used:** `actions/checkout@3d3c42e5…` (v7.0.1) and `actions-rust-lang/setup-rust-toolchain@ecabd13d…` (v2.0.0), both pinned by full commit SHA looked up from the actions' official repositories on 2026-10-27; tags recorded in trailing comments. `setup-rust-toolchain` was chosen because it reads `rust-toolchain.toml` (channel + components) when no `toolchain` input is given, and its `toolchain` input overrides the file — which is exactly how the MSRV job selects 1.89 (behavior confirmed from the action's README). Caching is enabled only for the gates job.
- **deny.toml license policy:** the allow list is the card's example list plus `GPL-3.0-only` (the package's own license, which cargo-deny checks as part of the graph) plus `Apache-2.0 WITH LLVM-exception` (needed by `rustix`, `linux-raw-sys`, `wasi` — see PQ-3). Licenses actually encountered in the 188-package tree: Apache-2.0, Apache-2.0 WITH LLVM-exception, MIT, Unicode-3.0 (`unicode-ident`), Zlib (`foldhash`), GPL-3.0-only. `ryu` is `Apache-2.0 OR BSL-1.0` and is satisfied via Apache-2.0, so BSL-1.0 was not added. `BSD-2-Clause`, `BSD-3-Clause`, `ISC` are unused (cargo-deny emits harmless "license-not-encountered" warnings). cargo-deny 0.20 removed the `copyleft` and `unlicensed` keys (Embark PR #611); the allow list itself is the gate, and its strictness was proven by removing `MIT` and observing rejection (§4).
- **Advisories:** `unmaintained = "all"` and `yanked = "deny"` (hard errors) in `[advisories]` v2; `cargo audit` exits 0 on the current tree (1,378 advisories in the DB, 188 dependencies scanned, no findings).
- **`clippy::expect_used`** is denied in `[lints.clippy]` beyond plan §11.3's list, matching SR-02's explicit mention of `expect_used` in plan v1.0.0 §7.
- **Arg classification design:** `classify_args` interprets exactly the first argument (clippy's `never_loop` correctly rejected the initial always-returning loop); the full flag parser is T-402's job. `ArgError` uses thiserror so the approved dependency is genuinely exercised.
- **README:** uses the card's exact one-line description; adds an explicit non-completeness disclaimer; lists no features.

**Assumptions** (per plan §0.2, written down): the card's "§20, O-7" reference is superseded by the card text itself (Owner confirmed "card wins"); "latest stable edition" means 2024; the enforcement-proof branch may contain the two formatting fixups without violating the "four separate commits" intent, since each violation still has a dedicated red run on an isolating commit.

## 7. Dependencies

| Crate | Requirement | Resolved | §9.2-style evaluation |
|---|---|---|---|
| `ratatui` | `=0.30.2` | 0.30.2 | Plan §9.1 **Approved** ("pin exact version"). Necessity: the planned TUI stack. Maintenance: active — 0.30.2 released 2026-06-19; no open advisories (`cargo audit` clean). License MIT (allowlisted). `unsafe`: none in ratatui itself; its `crossterm`/`rustix` dependencies contain `unsafe` syscall wrappers — accepted as part of the plan-approved stack (SR-01 governs *our* code; dependency `unsafe` review is §9.2 point 4 and the transport decision is ADR-009/T-105). Transitive: ~50 crates on Linux (~188 across all platforms, mostly windows/macos-only); no async runtime pulled in (tokio etc. are deny-listed and absent). MSRV 1.89 compatible. No network at runtime or build time. Included now, as the card directs, so audit/deny run against the real tree from the first commit. |
| `thiserror` | `2` | 2.0.21 | Plan §9.1 **Approved**. Necessity: error types with Display (§8.7; used by `ArgError`). Maintenance: 2.0.21 released 2026-09-23. Licenses MIT OR Apache-2.0. No `unsafe`. Transitive: proc-macro2/quote/syn only. MSRV 1.61. No build-time network. |

No other dependencies, and no dev-dependencies, were added.

## 8. Plan Questions

- **PQ-1** · Context: the task card header cites "Plan version: 1.1.0" and "plan §20, O-7" · What the plan says: the repository's `plan.md` is **v1.0.0** (Changelog has a single 1.0.0 entry); §20 lists O-1…O-6 only; §13's T-000 entry says "License field per ADR-014 is a placeholder (`publish = false`)" and ADR-014 is "Open (owner)" · Ambiguity/conflict: the card mandates `license = "GPL-3.0-only"`, a LICENSE file, SPDX headers and a CI SPDX gate — none of which v1.0.0 specifies; conversely the card references sections that do not exist in v1.0.0 · Options with consequences: (1) execute the card as the operative spec — done, per explicit Owner direction; (2) pause until the Owner pushes plan v1.1.0 — delays Phase 0; (3) follow v1.0.0 literally — weaker guarantees than the card (no LICENSE file, no SPDX gate), contradicting the Owner's stated intent · Executor's recommendation: publish plan v1.1.0 adding O-7 ("SPDX license identifier: GPL-3.0-only"), the T-000 license/SPDX requirements, and a Changelog entry, so the card and plan reconcile · Blocking? No — resolved by Owner direction during execution; flagged for Manager follow-up.
- **PQ-2** · Context: card §5.4 requires the LICENSE to be the verbatim text of https://www.gnu.org/licenses/gpl-3.0.txt, and mandates a blocking stop if it cannot be fetched; that host is unreachable from the execution sandbox (egress block) · What the plan says: nothing in v1.0.0 (license undecided, ADR-014 Open) · Ambiguity/conflict: the canonical file cannot be fetched byte-exact from gnu.org in this environment · Options with consequences: (1) use Debian's `/usr/share/common-licenses/GPL-3` — byte-identical to the canonical text (35,149 bytes; SHA-256 `3972dc97…36986`, the widely published gpl-3.0.txt checksum; correct first/last lines and structure; SPDX's own copy differs only because SPDX rewraps the text) — chosen by the Owner; (2) Owner supplies the file — no action pending; (3) hard block — stalls T-000 with a byte-identical copy already at hand · Executor's recommendation: option 1, with this provenance record; optionally re-verify the checksum once gnu.org is reachable · Blocking? No — resolved by Owner direction.
- **PQ-3** · Context: card §5.5 says not to add silently any license beyond the example list; the real tree requires **Apache-2.0 WITH LLVM-exception** (`rustix` 1.1.5, `linux-raw-sys` 0.12.1, `wasi` 0.11.1) · What the plan says: §9.2 criterion 3 expects licenses "compatible with deny.toml allowlist (MIT/Apache-2.0/BSD/ISC/Unicode)" — the LLVM-exception variant is not literally listed · Ambiguity/conflict: the exception grant is a narrow, well-understood addition to Apache-2.0 (patent termination), GPL-3.0-compatible per the FSF's license list, but it is outside the card's example set · Options with consequences: (1) allow it and report — done; (2) block on a plan change — would stall T-000 for a license both the FSF and SPDX treat as GPLv3-compatible; (3) attempt to avoid the crates — impossible, they are under the plan-approved ratatui stack · Executor's recommendation: keep it in the allow list (recorded here); the Manager may fold it into plan v1.1.0's allowlist text. Also recorded for completeness: `Zlib` (`foldhash` 0.2.0) and `Unicode-3.0` (`unicode-ident` 1.0.27) are in the tree but both are already in the card's example list; `ryu`'s `Apache-2.0 OR BSL-1.0` resolves through Apache-2.0 without adding BSL-1.0 · Blocking? No.

## 9. Security and privacy notes

- **Untrusted inputs touched:** command-line arguments only. They are read via `std::env::args_os()` (never panicking on non-UTF-8), converted with an explicit `to_str()` check, and mapped to a typed `ArgError` printed as one stderr line with exit code 2 — no panic is reachable from argv (tested with raw bytes `0xff 0xfe 0xfd`). No files, no network, no environment parsing.
- **SR-01/SR-02/SR-03 enforced mechanically** (`unsafe_code = "forbid"`; the eight denied clippy lints; test-only relief confined to `clippy.toml`; the print allows confined to three functions in `main.rs` behind a justification comment) — and their enforcement is itself proven by the four red CI runs in §4.
- **Supply chain:** `Cargo.lock` committed; every Cargo command that resolves dependencies runs `--locked`; sources restricted to crates.io (`unknown-registry`/`unknown-git` denied); prohibited crates deny-listed and absent from the tree; CI actions pinned by commit SHA; cargo-audit/cargo-deny installed from official releases at pinned versions with SHA-256 verification of the tarballs; advisories (vulnerabilities, unmaintained, yanked) are hard errors.
- **Secrets:** the GitHub token used for pushing and PR creation exists only in the sandbox environment; it is not present in any committed file, log, or report (all command output was redacted). It was transmitted in the task message, so the Owner should rotate it (see §11). No real MAC addresses, hostnames, or network details were handled.

## 10. Known issues and limitations

- The enforcement-proof PR (#2) is intentionally left open and unmerged, per the Owner's instruction; its branch ends in violation (d) by design.
- `cargo deny check` emits three informational `license-not-encountered` warnings (BSD-2-Clause, BSD-3-Clause, ISC) and one `multiple-versions` warning (`syn` 2.0.119 and 3.0.9 coexist) — both categories are warnings by policy (§5.5) and do not fail the gate.
- plan v1.0.0 vs card v1.1.0 remains unreconciled in the repository (PQ-1) until the Manager publishes the updated plan.
- CI has not yet been observed on a `push` to `main` (nothing has been merged); the `pull_request` path is fully exercised.

## 11. Suggested follow-ups

1. Manager: publish plan v1.1.0 — add O-7 (license = GPL-3.0-only), the T-000 license/SPDX requirements, `Apache-2.0 WITH LLVM-exception` in the §9.2 license wording, and a Changelog entry (resolves PQ-1/PQ-3).
2. Owner: rotate the GitHub token used for this task, since it traveled in plaintext in the task message.
3. Proceed with T-001 (ADR records) and T-002 (core primitives) per the dependency graph; both only need T-000.
