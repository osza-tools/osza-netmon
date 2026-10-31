# ADR-017: Interface data source

- **Status:** Accepted (PQ-1 resolved by Manager decision, 2026-10-31)
- **Date:** 2026-10-31 · **Deciding task / owner:** T-101 / Executor proposes, Manager confirms

## Context

Source: task card T-101 §3 ("ADR documenting the interface data source chosen (e.g., `getifaddrs` via safe wrapper, `/sys/class/net`, or `nix`)") and §8 ("No new dependencies unless approved via §9.2 evaluation in the execution report. If you need a crate (e.g., `nix` for `getifaddrs`), evaluate it against all 7 criteria in §9.2 and raise a Plan Question before adding it."). Plan §6.2 FR-SC-01 requires, per interface: name, index, MAC, **IPv4 address with prefix**, link type, up/running state — plus the default-route gateway, which the same card assigns to the pure `/proc/net/route` parser (plan Appendix E).

Binding constraints: SR-01 (`unsafe_code = "forbid"` — no FFI of our own), §9.1 dependency policy (nix is listed as a *candidate* crate for the transport decision, decision by ADR in the named task), Linux-only product (AF_PACKET, `/proc`, netns per plan §11.2).

## Options considered

1. **Own FFI wrapper around `getifaddrs(3)` (libc, hand-written).** Rejected: requires `unsafe` in our code, which SR-01 forbids outright.
2. **`/sys/class/net` (pure std).** Rejected as the primary source: sysfs provides name, `ifindex`, `address` (MAC), `type` (ARPHRD) and `flags`, but **no per-interface IPv4 address or netmask** — addresses live in the kernel's address family data, not sysfs. `/proc/net/route` carries only the connected-subnet route (network + mask, not the interface's own address), and `/proc/net/fib_trie` lists local addresses **without interface attribution**, so multi-interface hosts cannot be mapped. FR-SC-01 is not satisfiable from sysfs + `/proc` alone.
3. **`nix` crate — `getifaddrs(3)` behind its safe wrapper.** Chosen. One call returns, per interface, the `AF_PACKET` record (name, index, hardware address, `ARPHRD` link type) and the `AF_INET` records (address + netmask → prefix), plus the `IFF_UP`/`IFF_RUNNING`/`IFF_LOOPBACK` flags; `/proc/net/route` (pure std, bounded read) adds the default gateways.
4. **Other crates** (`if-addrs`, `network-interface`, `pnet_datalink`): not in the §9.1 candidate list (a Plan Question each); `pnet_datalink` is the T-105 transport candidate and is far heavier than interface enumeration needs.

## Decision

Use **`nix` 0.31.3** (exact pin, `default-features = false`, only the `net` feature enabled) for `getifaddrs(3)`, plus the pure-std `/proc/net/route` parser of the same task for default gateways. Evaluation against the seven criteria of plan §9.2:

| # | Criterion | Result |
|---|---|---|
| 1 | **Necessity / smallest alternative** | The smallest std-only alternative (sysfs, option 2) cannot supply the per-interface IPv4 address/prefix that FR-SC-01 mandates; the only std-reachable source of that data is `getifaddrs(3)`, and every way to call it without a crate requires `unsafe` (SR-01). `nix` is the smallest *safe* wrapper. |
| 2 | **Maintenance** | nix 0.31.3 (2026-05-11 release line; crate actively maintained, 0.31.x is current). `cargo audit`: no advisories against nix or its transitive deps. |
| 3 | **License** | nix is MIT; transitive deps libc 0.2.191 (MIT OR Apache-2.0), bitflags 2.13.2 (MIT OR Apache-2.0), cfg-if 1.0.5 (MIT OR Apache-2.0), memoffset 0.9.1 (MIT) — all inside the `deny.toml` allowlist; `cargo deny check` licenses **ok**. |
| 4 | **`unsafe` footprint** | nix wraps the libc call internally (`getifaddrs`/`freeifaddrs` + sockaddr decoding); its public API is safe and our crate keeps `unsafe_code = "forbid"` — verified by the CI gates on this changeset. No `unsafe` is added to *our* code. |
| 5 | **Transitive dependencies / build cost** | **Zero new crates in the graph**: `nix` reuses bitflags, cfg-if, libc and memoffset versions already locked for the ratatui tree — the `Cargo.lock` diff is exactly one line (`"nix 0.31.3"` added to our dependency list). No async runtime, no build scripts that fetch data. |
| 6 | **MSRV** | nix 0.31.3 declares `rust-version = 1.69`; the MSRV job (`rustup run 1.89.0 cargo build --locked`) is green on this changeset. |
| 7 | **Our constraints** | No network at runtime (a `getifaddrs` call is a local kernel query — no socket, no packet, plan §2.3 untouched); no network at build time; works unprivileged (ADR-005 — `getifaddrs` needs no capability). |

## Consequences (positive, negative, follow-ups)

**Positive**

- Every FR-SC-01 field from one syscall-backed, kernel-maintained API; no fragile sysfs/fib_trie scraping.
- No new crates in the dependency graph (§9.2 criterion 5 above); supply-chain surface (audit/deny/MSRV) unchanged in size.
- `unsafe` stays forbidden in our code; the wrapper boundary is nix's, reviewed upstream.

**Negative**

- A new direct dependency requires Manager approval — raised as **PQ-1** in the T-101 execution report per card §8; if declined, the fallback is sysfs-only with an amended FR-SC-01 (losing the IPv4/prefix field), which the report argues against.
- The `AF_PACKET` sockaddr accessor (`as_link_addr`) is Linux-specific — consistent with the plan's Linux-only architecture (AF_PACKET in ADR-005, netns scenarios in §11.2), but a port would need a different source.
- nix is a broad API surface; mitigated by enabling only the `net` feature and pinning the exact version, same policy as ratatui (plan §9.1).

**Follow-ups**

- T-105 (transport decision, ADR-009) evaluates `nix`/`pnet_datalink`/`socket2` for raw sockets; if T-105 also picks nix, this dependency is shared, not duplicated.
- Revisit the pin at gate G-1 alongside the other pinned crates.

## Evidence (links to PoC data, reports, benchmarks)

- `docs/reports/T-101/execution-01.md` §7 — full §9.2 evaluation as required by the card, gate outputs, lock diff (one line).
- Probing transcript of `getifaddrs` on a live system (synthetic sandbox): per-interface `AF_PACKET` records (index, MAC, `ARPHRD`) and `AF_INET` records (address + netmask) — recorded in the T-101 report §6, decision D-1.
- CI run on the task branch (all §11.3 gates green) — linked in the T-101 execution report.
