# osza-netmon — Project Plan

| | |
|---|---|
| **Document** | `plan.md` — the single source of truth for this project |
| **Plan version** | 1.1.0 |
| **Targets product version** | 0.1.0 (MVP) |
| **Status** | Approved for execution — Phase 0 may start |
| **Ecosystem** | osza-tools |
| **Product name** | `osza-netmon` (confirmed, ADR-001) |
| **Repository** | https://github.com/osza-tools/osza-netmon |
| **License** | GPL-3.0 (ADR-014; variant to confirm, O-7) |
| **Stack** | Rust · Terminal UI (ratatui) · Linux |
| **Roles** | Owner (human, relays orders and reports) · Manager (lead agent: plan, task cards, report review, gate decisions) · Executor agent(s) · Reviewer agent(s) |

---

## 0. Document Control

### 0.1 Purpose
This file is the authoritative reference for what we build, why, how it is structured, how it is tested, and how work is assigned and verified. Task cards given to agents are derived from it. Agents never need to guess intent: if something is not specified here or in their task card, they **stop and raise a Plan Question** (§14.5).

### 0.2 Precedence (highest first)
1. Principles, scope boundaries and security requirements (§1, §2, §7).
2. The rest of this plan.
3. The current task card.
4. `AGENTS.md` (derived from Appendix F).
5. An agent's own assumptions (lowest; must be written down in the report).

A conflict between any two levels is never resolved silently. It becomes a Plan Question.

### 0.3 Change control
Only the Manager edits this file. Every change bumps the plan version and adds a line to the Changelog (§22). Agents may *propose* changes through Plan Questions or review findings; they never edit `plan.md` themselves.

### 0.4 Requirement language
**MUST / MUST NOT** = mandatory, verified by acceptance criteria. **SHOULD** = expected unless a documented reason exists. **MAY** = optional.

### 0.5 Identifier scheme
`ADR-nnn` decisions · `FR-xx-nn` functional requirements · `SR-nn` security requirements · `NFR-nn` non-functional requirements · `AC-nn` MVP acceptance criteria · `T-nnn` tasks · `G-n` phase gates · `R-nn` risks.

### 0.6 Persistence of project state
The Manager does not retain memory between sessions. Therefore project state lives in this file (§21 Status Board, §22 Changelog) and in `docs/reports/`. At the start of any new session, the Owner provides: the latest `plan.md` and the most recent reports.

---

## 1. Mission and Principles

### 1.1 Mission
A lightweight terminal application that discovers devices on a directly connected local IPv4 network and presents the information it actually has about each device in a clear, interactive interface — while stating honestly what it does not know.

> **One tool. One clear responsibility. Do it well.**
> *Discover local devices. Show what is known. Make the information easy to inspect. Do not pretend to know what cannot be determined.*

### 1.2 The four questions (definition of success)
A person responsible for a small network must be able to answer, quickly and without training:
1. Which devices have been discovered?
2. What information is available about each?
3. Which have been observed recently?
4. What remains unknown?

**Scope gate:** a feature enters the product only if it serves one of these four questions. Everything else goes to the backlog (§18).

### 1.3 Principles
| # | Principle | Practical meaning |
|---|---|---|
| P1 | One responsibility | Discovery and inspection only. No admin, no IDS, no analytics. |
| P2 | Honesty over completeness | Never claim the list is complete. Never invent data. Unknown is shown explicitly. |
| P3 | Observed claims, not verified identities | ARP has no authentication. Everything shown is "observed", never "verified". |
| P4 | Safe by default | Local subnet only, bounded effort, least privilege, no data leaves the machine. |
| P5 | Simplicity | Smallest design that meets the requirement. No speculative abstraction. No shared crate with other osza tools until a second tool needs the same code. |
| P6 | Always responsive | The UI thread never waits on network or disk I/O. |
| P7 | All external input is hostile | Packets, DNS answers, files in `/proc`, and terminal sizes are untrusted. |
| P8 | Testable by construction | Time, I/O and randomness are injected behind small traits. |

---

## 2. Scope

### 2.1 In scope (MVP 0.1.0)
- Local IPv4 interface and subnet selection with confirmation.
- Reading the OS neighbor table.
- Low-impact active ARP discovery inside the selected subnet.
- In-memory device registry: duplicate handling, first/last seen, Recent/Idle status.
- IPv4, MAC, hostname (best effort), vendor (offline database) per device.
- Device details view; manual refresh and periodic rediscovery.
- Keyboard-first TUI with visible, clickable controls.
- Explicit handling of missing data, permission errors, discovery failures.
- Authorization notice; read-only fallback when privileges are missing.

### 2.2 Out of scope (MVP) — must not be implemented
Per-device bandwidth · packet capture or payload analysis · port scanning · any TCP/UDP probe of devices · ICMP ping sweeps · mDNS/NetBIOS/SSDP/UPnP queries · Nmap · OS fingerprinting · ARP-spoofing/intrusion detection · threat scoring or alerts · traffic graphs · router administration · servers, cloud or remote collection · history databases · JSON/CSV export · IPv6 discovery · GUI · user-defined remote ranges · device nicknames/persistence (backlog).

### 2.3 Network footprint rule
The only traffic the product may originate is:
1. ARP requests inside the confirmed subnet (active mode only).
2. DNS PTR queries to an eligible **local** resolver (ADR-003), unless disabled.

Anything else requires a plan change.

---

## 3. Users, UX Goals and Budgets

### 3.1 Primary user
A technical person (administrator, consultant, support technician, hobbyist) running the tool on a laptop or a Raspberry Pi, locally or over SSH, on a home, restaurant, hotel or small-office network. Non-technical owners are served indirectly; the product does not target them in 0.1.0.

### 3.2 First 60 seconds
Launch → (first run only: acknowledge notice) → one `Enter` to confirm the suggested network → devices appear **progressively** while scanning → user can open a device and understand its fields.
Any additional step before the first device appears needs a written justification.

### 3.3 UX principles
- Compact main table; detail on demand.
- Every visible control has a keyboard equivalent; mouse is an enhancement.
- Color never carries meaning alone (labels carry it; `NO_COLOR` is honored).
- Messages say what happened, why, and what to do next.
- Wording follows the controlled vocabulary in §5.4.

### 3.4 Non-functional requirements and budgets
| ID | Requirement | Measure |
|---|---|---|
| NFR-01 | First device visible ≤ 3 s after scope confirmation (typical /24) | timed on reference network |
| NFR-02 | Full active cycle on a /24 (2 passes) ≤ 10 s | timed |
| NFR-03 | No event-loop iteration blocks > 100 ms | debug instrumentation + test |
| NFR-04 | Idle CPU < 1% of one core over 60 s; wake-ups only for timers/input | `pidstat`/`top` |
| NFR-05 | RSS ≤ 50 MB at 1,000 devices; hard registry cap 4,096 | measured |
| NFR-06 | Traffic limited to §2.3, ≤ configured pps (default 100) | packet counting in netns |
| NFR-07 | Time to first screen ≤ 500 ms | timed |
| NFR-08 | Works at 80×24 minimum, over SSH and tmux; shows a "terminal too small" screen below that; `NO_COLOR` honored; usable without mouse | manual + snapshot tests |
| NFR-09 | Zero panics from malformed external input | fuzz + property tests |
| NFR-10 | Stripped release binary including vendor DB ≤ 10 MB (informational) | reported |

**Platform (PROVISIONAL, confirm in §20):** Linux, x86_64 and aarch64, glibc distributions (Ubuntu LTS, Debian stable, Raspberry Pi OS), kernel ≥ 5.4.

---

## 4. Decision Log

Decisions are recorded as ADRs in `docs/adr/` (task T-001). Status: **Accepted**, **Provisional** (accepted, owner confirmation pending), **Pending** (decided by evidence in a named task), **Open** (owner decision).

| ADR | Title | Status |
|---|---|---|
| 001 | Product naming | Accepted |
| 002 | Status vocabulary (Recent / Idle) | Accepted |
| 003 | Hostname resolution policy | Accepted |
| 004 | Authorization notice policy | Accepted |
| 005 | Privilege model | Accepted (mechanism details Pending T-104/T-105) |
| 006 | Single-package repository (lib + bin) | Accepted |
| 007 | Aging model (scan-cycle based) | Accepted |
| 008 | Device identity and shared-MAC handling | Accepted |
| 009 | Discovery transport library | Pending (T-105) |
| 010 | Neighbor-table source (`/proc/net/arp` vs netlink) | Pending (T-105) |
| 011 | Probe strategy (passes, rate, sender IP, unicast refresh) | Pending (T-105), defaults below |
| 012 | Concurrency: std threads, no async runtime | Accepted |
| 013 | Persistence: none, except the notice acknowledgment | Accepted |
| 014 | Project license | Accepted (variant to confirm, O-7) |
| 015 | DNS PTR client implementation | Pending (T-203) |
| 016 | CI provider: GitHub Actions | Accepted |

### ADR-001 Naming — Accepted
The source brief mixes `osza-tools` and `veex-tools`. Names: ecosystem `osza-tools`; crate and binary `osza-netmon`; display name "osza Network Monitor". The name MUST live in exactly one place in code (`pub const APP_NAME`/`DISPLAY_NAME`) plus `Cargo.toml`, so a rename is a one-commit change. The Owner confirmed the name and created the repository at https://github.com/osza-tools/osza-netmon.

### ADR-002 Status vocabulary — Accepted
The Linux kernel uses `STALE` for a different concept. To avoid confusion in code, docs and UI we use **Recent** and **Idle**. "Stale" MUST NOT appear in our code identifiers or UI. Property-level absence uses `Unknown` / `Unavailable` (§5.2).

### ADR-003 Hostname resolution policy — Accepted
Reverse DNS for local addresses can leak device information to external resolvers. Policy:
1. Hostname lookups use **PTR queries sent directly to an eligible local resolver**, never through the libc/NSS resolver (which may forward upstream or involve other name services).
2. Eligible resolver = a nameserver address from `/etc/resolv.conf` that lies **inside the selected subnet** (loopback stubs such as `127.0.0.53` are not eligible; if only a loopback stub is listed and `/run/systemd/resolve/resolv.conf` exists, use that file's entries under the same rule).
3. If no eligible resolver exists, hostname is `Unavailable (no local resolver)`. No fallback to other servers.
4. 1 s timeout, one retry, bounded queue, one lookup per (MAC, IP) pair, failed lookups retried no more than every 5 minutes.
5. `--no-hostnames` disables the feature. The help screen explains what is queried and where it goes.
6. Residual risk (a LAN resolver may forward PTR queries upstream) is documented in `docs/limitations.md`.

### ADR-004 Authorization notice policy — Accepted
- First run, or whenever the notice text version changes: a full-screen notice requiring explicit acknowledgment (`y`) before **any** discovery. The acknowledgment (notice version + timestamp) is stored in `$XDG_CONFIG_HOME/osza-netmon/notice-ack` (fallback `~/.config/...`), mode `0600`. If it cannot be written, the app continues and asks again next run (non-fatal).
- Every run: a one-line reminder in the dashboard header and on the scope screen ("Authorized networks only. Active discovery sends ARP requests.").
- Notice text (the product name is substituted):
  > {DISPLAY_NAME} is intended only for networks you own or are explicitly authorized to monitor. Local discovery sends network probes. Use this tool only within an authorized network.
- This is the only persisted state in the MVP (ADR-013).

### ADR-005 Privilege model — Accepted
1. The process runs as an unprivileged user. It is never setuid and never re-executes itself through `sudo`.
2. Before the TUI starts, it tries to open one `AF_PACKET` socket bound to the selected interface and `ETH_P_ARP`. This needs `CAP_NET_RAW`, granted to the binary by `setcap cap_net_raw+ep`.
3. After the socket is open, the process **drops its capabilities** (effective, permitted, inheritable, ambient) and sets `no_new_privs`, before it processes any untrusted input. Tests verify `CapEff`/`CapPrm` in `/proc/self/status` are zero afterwards.
4. If the socket cannot be opened (`EPERM`), the app starts in **read-only mode** (neighbor table only) with an actionable message — not an error exit.
5. If started with euid 0, the app warns once ("running as root is not required; use file capabilities") and still drops capabilities.
6. `docs/permissions.md` documents the trade-off: file capabilities allow any user who can execute the binary to open a raw socket; recommend restricting execution by group (`chgrp`/`chmod 750`).
7. Capability library candidates: `caps` or `capctl` (the latter's last release was March 2024). Chosen in T-104 under §9 criteria; `unsafe` stays forbidden in our own code.
8. Rejected: triggering ARP via UDP/TCP connects to every address (touches ports, unreliable, violates §2.3).

### ADR-006 Repository structure — Accepted
One Cargo package with `lib.rs` + `main.rs`. No workspace and no shared crate with other osza tools until a second tool needs the same code. Dev-only tools live in `examples/`; fuzz targets in a separate `fuzz/` package excluded from builds.

### ADR-007 Aging model — Accepted
A device becomes **Idle** only when **both** hold:
- it was absent from `idle_after_cycles` (default **3**) *consecutive complete scan cycles*, and
- `now − last_seen ≥ idle_min_age` (default **120 s**).

Only cycles with outcome `Complete` age devices; `Partial`, `Failed` and `Cancelled` cycles never do. The age floor prevents manual-refresh spamming from idling everything within seconds. Any new observation immediately returns a device to **Recent**. In read-only mode a successful neighbor-table read is one cycle; because kernel entries linger, Idle appears later in that mode (documented).

### ADR-008 Identity and shared-MAC handling — Accepted
- Identity key = `(interface_index, MAC)`. IPv4 addresses are observed properties; a device keeps every IP seen this session, with first/last seen per IP; its **primary IP** is the most recently observed one.
- If one IP is observed under two MACs, each record keeps it in its history; neutral note in Details ("also observed under MAC …"). No alert, no red, no verdict.
- If one MAC is observed with ≥ `shared_mac_threshold` (default **5**) distinct IPs seen within the idle window, it gets the tag **Multiple IPs** with a neutral explanation (router, proxy ARP, or virtual interfaces). Records are never merged across different MACs.
- Devices are never removed during a session; they become Idle.
- The registry hard cap is **4,096** keys. Beyond it, new keys are dropped, existing ones still update, and a persistent warning is shown.

### ADR-009/010/011 Pending, with provisional defaults for implementation
- **ADR-009 transport.** Candidates: `pnet_datalink` (its latest release, 0.35.0, dates from May 2024 — slow cadence; do not assume it), `nix` safe wrappers, `socket2`. Criteria in §9.2; also the transport is hidden behind the `ArpTransport` trait so replacing it costs one module.
- **ADR-010 neighbor source.** `/proc/net/arp` (simple; no state) vs netlink `RTM_GETNEIGH` (state: reachable/stale/failed). T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency.
- **ADR-011 probe strategy.** Provisional defaults: sender IP = interface IP; **100 packets/s**; initial scan and manual refresh use **2 passes** (second pass only to addresses that did not answer, after ≥ 1 s); periodic rediscovery uses **1 pass**; listen window **1.5 s** after the last send. T-105 also evaluates sender `0.0.0.0` (RFC 5227 style probes) and unicast ARP refresh of known devices.

### ADR-012 / 013
- **012:** `std::thread` + bounded channels. No tokio or other async runtime in the MVP.
- **013:** In-memory state per session. No config file in the MVP; options come from CLI flags. The notice acknowledgment is the sole persisted item.

### ADR-014 License — Accepted
The Owner chose **GPL-3.0**. Until the Owner states otherwise (O-7) the SPDX identifier is `GPL-3.0-only` (the literal reading); `GPL-3.0-or-later` is the alternative. Consequences:
- The repository carries a verbatim `LICENSE` file (text from https://www.gnu.org/licenses/gpl-3.0.txt — never paraphrased or reproduced from memory), `license = "GPL-3.0-only"` in `Cargo.toml`, and every `.rs` file starts with `// SPDX-License-Identifier: GPL-3.0-only`. CI enforces the header.
- The `deny.toml` license allowlist contains only licenses compatible with GPL-3.0 (for example MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0). Apache-2.0 is compatible with GPLv3. Any other license needs a Plan Question.
- The IEEE-derived vendor data is data, not our code; its source, terms and attribution are recorded in `data/oui/SOURCE.md` (T-202).
- `publish = false` stays in `Cargo.toml` until the Owner decides to publish on crates.io.

### ADR-016 CI — Accepted
GitHub Actions on the repository above. Every action is pinned by full commit SHA; workflows use `permissions: contents: read` unless a job needs more. The netns job uses `sudo` on a GitHub-hosted Ubuntu runner; whether it works as expected, including `tc netem` availability, is verified in T-106.

---

## 5. Domain Model and Vocabulary

### 5.1 Glossary
| Term | Meaning |
|---|---|
| **Scope** | The selected interface and its directly connected IPv4 network; the only area probed. |
| **Observation** | One piece of evidence that `(MAC, IPv4)` exists on an interface at a time, with its **source**. |
| **Source** | `LocalInterface`, `NeighborTable`, `ArpReply`, `ReverseDns`, `VendorDb`. |
| **Scan cycle** | One discovery run: neighbor read → ARP passes → neighbor read (active mode), or one neighbor read (read-only). Has a `ScanId`. |
| **Scan outcome** | `Complete`, `Partial(reason)`, `Failed(error)`, `Cancelled`. |
| **Device record** | Registry entry keyed by `(interface_index, MAC)`. |
| **Status** | `Recent` or `Idle` (§4 ADR-007). Describes observation history only — never current association. |
| **Tag** | `This device`, `Gateway`, `Private address`, `Multiple IPs`. Factual labels, never verdicts. |
| **Field state** | `Known(value, source)`, `Pending`, `Unknown`, `Unavailable(reason)`. |

**Field state semantics.** `Unknown` = lookup was possible and returned nothing reliable. `Unavailable` = lookup could not be performed (disabled, no resolver, error). `Pending` = queued, shown as `…`. The UI shows these words explicitly and never fills a gap with a guess.

### 5.2 Illustrative types (not binding; names may change)
```rust
pub struct MacAddr([u8; 6]);          // is_multicast(), is_locally_administered(), Display aa:bb:cc:dd:ee:ff
pub struct Hostname(String);          // ONLY constructible by validation: ASCII [A-Za-z0-9._-], <= 253
pub struct DisplayText(String);       // sanitized free text (vendor names), <= 64 chars, no control/bidi chars
pub enum  Field<T> { Known { value: T, source: Source }, Pending, Unknown, Unavailable(Reason) }
pub struct DeviceKey { iface_index: u32, mac: MacAddr }
pub struct IpRecord { ip: Ipv4Addr, first_seen: Timestamp, last_seen: Timestamp }
pub struct Timestamp { mono: Instant, wall: SystemTime }   // mono for logic, wall for display only
pub enum  Status { Recent, Idle }
pub struct Device { key: DeviceKey, ips: Vec<IpRecord>, hostname: Field<Hostname>,
                    vendor: Field<DisplayText>, tags: Tags, first_seen: Timestamp, last_seen: Timestamp,
                    missed_cycles: u32, sources: SourceSet, notes: Vec<Note> }
```

### 5.3 Derived labels
- **Private address:** MAC with the locally-administered bit set. Shown in the Vendor column as `Private address`; Details explain: "often a phone using a Wi-Fi privacy feature, but virtual machines and containers also use these". This is a label, not a claim about the device type, and no cross-MAC correlation is attempted.
- **Invalid MAC:** multicast/broadcast/all-zero sender MACs are rejected at the boundary.
- **This device:** the selected interface's own MAC/IP, inserted from interface data (nobody ARPs itself). Source `LocalInterface`.
- **Gateway:** the device whose IP equals the default-route gateway of the selected interface (from `/proc/net/route`), applied only after that device has been observed.

### 5.4 Controlled vocabulary
**Use:** observed · recently observed · idle · not seen recently · unknown · unavailable · private address · multiple IPs.
**Never use (UI, docs, code identifiers for user-facing text):** online · offline · connected · disconnected · intruder · unauthorized · rogue · suspicious · malicious · safe · trusted · secure · verified · stale. A review check greps for these (§11.7).

---

## 6. Functional Requirements

### 6.1 Startup and notice (FR-ST)
| ID | Requirement |
|---|---|
| FR-ST-01 | MUST show the authorization notice per ADR-004 before any discovery (including read-only mode). Keys: `y` acknowledge, `q` quit. |
| FR-ST-02 | MUST NOT send any probe before the notice is acknowledged and the scope is confirmed. |
| FR-ST-03 | MUST then show the scope screen (FR-SC) and, after confirmation, start the first scan immediately. |
| FR-ST-04 | MUST show a "terminal too small" screen below 80×24 instead of a broken layout; resizing back recovers automatically. |

### 6.2 Interface and scope (FR-SC)
| ID | Requirement |
|---|---|
| FR-SC-01 | MUST enumerate interfaces with: name, index, MAC, IPv4/prefix, link type, up/running state, and default-route gateway if any. |
| FR-SC-02 | MUST suggest one interface: the one carrying the default route; else the highest-ranked eligible interface. Virtual interfaces (`docker*`, `veth*`, `br-*`, `virbr*`, `tun*`, `tap*`, `wg*`, `lo`) rank last and are labeled `virtual`. |
| FR-SC-03 | Eligibility: up, Ethernet-type link (ARP-capable), has an IPv4 address, not loopback. Ineligible interfaces are listed disabled **with the reason**. |
| FR-SC-04 | Scope MUST equal the interface's own IPv4 network. Arbitrary or remote ranges are not accepted (CLI included). |
| FR-SC-05 | Probe targets exclude the network address, the broadcast address and the interface's own address. `/31` probes both addresses; `/32` has no probe targets (read-only only, with explanation). |
| FR-SC-06 | Default active-scan cap: **1,022 hosts (/22)**. Larger networks require `--max-hosts N` (absolute ceiling 65,534) **and** an in-app confirmation showing the packet count and estimated duration. |
| FR-SC-07 | If the subnet is not private/link-local/CGNAT (RFC 1918, 169.254/16, 100.64/10), active discovery requires an extra explicit confirmation (type `yes`). Read-only mode needs none. |
| FR-SC-08 | The screen MUST show the number of ARP requests that active mode will send and the mode (active / read-only). |

### 6.3 Discovery (FR-DS)
| ID | Requirement |
|---|---|
| FR-DS-01 | Each cycle MUST read the neighbor table before the sweep (instant first rows) and again after it. |
| FR-DS-02 | Neighbor entries MUST be filtered: selected interface only; IP inside scope; complete entries only (drop incomplete/failed); MAC not zero/broadcast/multicast. |
| FR-DS-03 | Active mode MUST send ARP requests only to scope targets, with sender MAC/IP = the interface's own (until ADR-011 says otherwise). |
| FR-DS-04 | Sending MUST be paced (default 100 pps; configurable with `--rate`, max 500). |
| FR-DS-05 | Passes and listen window per ADR-011 defaults. |
| FR-DS-06 | Replies MUST be accepted only if **all** hold: EtherType ARP; hardware type Ethernet; protocol type IPv4; hw len 6; proto len 4; opcode reply; Ethernet destination = our MAC; Ethernet source = ARP sender MAC; sender MAC valid (§5.3); sender IP inside scope, not network/broadcast/own; sender IP is **one we requested in the current scan** (solicited-only). Everything else is dropped and counted (counters shown in Details→debug only). |
| FR-DS-07 | The app MUST NOT passively collect other hosts' ARP traffic. |
| FR-DS-08 | One scan at a time. `Refresh` during a scan shows "Scan already in progress" and queues nothing. |
| FR-DS-09 | Every blocking wait has a timeout; a scan can be cancelled promptly (≤ 250 ms) on quit or error. |
| FR-DS-10 | Observations stream to the UI progressively (batched ≤ every 50 ms). |
| FR-DS-11 | Outcome classification: `Complete` (all targets sent and window elapsed); `Partial` (some send errors/short writes — states count); `Failed` (socket/permission/interface lost); `Cancelled`. |
| FR-DS-12 | Periodic rediscovery: default **60 s after the previous cycle finished** (never overlapping); `--interval 0` = manual only; minimum accepted 15 s. After a `Failed` cycle, retry no sooner than 30 s; after 3 consecutive failures stop auto-scans, keep the error visible, allow manual refresh. |
| FR-DS-13 | No other probe types exist (§2.3). |
| FR-DS-14 | Read-only mode (no socket): neighbor reads only, same cycle/aging rules, header shows `Mode: read-only` and how to enable active mode. |

### 6.4 Registry (FR-RG)
| ID | Requirement |
|---|---|
| FR-RG-01 | Single owner (the app state on the main thread). Workers only send events. |
| FR-RG-02 | Merge by `DeviceKey`; update `last_seen`, IP history, `sources`; `first_seen` is set once per session. |
| FR-RG-03 | `begin_cycle(id)` / `observe(obs)` / `end_cycle(id, outcome)` API. Observations tagged with a non-current `ScanId` are ignored. |
| FR-RG-04 | Aging, tags, shared-MAC, IP-conflict note and cap per ADR-007/008. |
| FR-RG-05 | The registry takes the current time as a parameter (injected clock). No `sleep` in tests. |
| FR-RG-06 | Sorting by IPv4 (numeric `Ipv4Addr` order) or hostname (unknown hostnames last, then by IP). Sort is stable. Selection is bound to `DeviceKey`, not row index, so the highlight stays on the same device across updates and re-sorts. |
| FR-RG-07 | Conflicting or incomplete data is preserved and represented honestly; never silently overwritten with guesses. |

### 6.5 Enrichment (FR-EN)
| ID | Requirement |
|---|---|
| FR-EN-01 | Vendor lookup uses the embedded offline IEEE-derived database with **longest-prefix match** across MA-S (36-bit), MA-M (28-bit) and MA-L (24-bit) blocks. No match → `Unknown`. Locally-administered MAC → `Private address` (no lookup). |
| FR-EN-02 | The database records its source files, retrieval date and checksums; the help screen shows the database date. |
| FR-EN-03 | Hostname lookup per ADR-003, on its own worker thread, never blocking the UI. |
| FR-EN-04 | All strings from the network or data files pass through validating constructors (`Hostname`, `DisplayText`) at the model boundary. Raw strings never reach the UI layer. |
| FR-EN-05 | Vendor/hostname are informational; the UI says so in Details (§10.4). |

### 6.6 Terminal UI (FR-UI)
Specified in §10. Summary requirements:
| ID | Requirement |
|---|---|
| FR-UI-01 | Dashboard with header, device table, action bar; adapts to resize (≥ 80×24). |
| FR-UI-02 | Details screen with Identity / Observation / Information sources sections and a Back action preserving registry and selection. |
| FR-UI-03 | Help screen (keys, vocabulary, limits, notices, database date, recent messages). |
| FR-UI-04 | Mandatory keyboard map (§10.3); optional mouse support (§10.5). |
| FR-UI-05 | Missing values shown as `Unknown` / `Unavailable` / `…`. |
| FR-UI-06 | Terminal is restored on quit, on recoverable errors, on panic, and on SIGTERM/SIGHUP. |
| FR-UI-07 | Redraw only when state changed or for the 1 Hz relative-time tick. |

### 6.7 CLI (FR-CF)
| Flag | Meaning |
|---|---|
| `--interface <name>` | Preselect interface (still goes through confirmation). |
| `--interval <seconds>` | Rediscovery interval; `0` = manual only; min 15. |
| `--rate <pps>` | ARP send rate (default 100, max 500). |
| `--max-hosts <n>` | Raise the 1,022-host cap (ceiling 65,534). |
| `--read-only` | Never open a raw socket. |
| `--no-hostnames` | Disable reverse-DNS lookups. |
| `--no-mouse` | Do not enable mouse capture. |
| `--debug-log <path>` | Write a debug log (file mode `0600`; may contain MACs/hostnames; the app warns before starting). |
| `--version`, `--help` | Standard. |

No config file in the MVP. A minimal argument parser is preferred (`lexopt`/`pico-args`; `clap` only if justified).

### 6.8 Errors and degraded modes (FR-ER)
Every error maps to a user message with **what happened · why · what to do**, shown in one line in the action bar with details in Help→Messages. Required cases:

| Case | Behavior |
|---|---|
| No `CAP_NET_RAW` | Start read-only; message with the exact `setcap` command reference (`docs/permissions.md`). |
| No eligible interface / no IPv4 | Scope screen explains; read-only unavailable too if no interface; clean exit with message when nothing is selectable. |
| Interface goes down mid-session | Scan `Failed`; keep registry; show error (red); retry per FR-DS-12. |
| Neighbor table unreadable | Continue with ARP only; message. |
| Resolver unavailable | Hostnames `Unavailable`; one message, not repeated per device. |
| Registry cap reached | Persistent warning; existing devices still update. |
| Terminal too small / resized | FR-ST-04. |
| Internal inconsistency | Terminal restored, error printed to stderr after restore, non-zero exit. |

---

## 7. Security and Privacy Requirements

### 7.1 Threat model (summary)
| Asset | Threat / actor | Mitigation |
|---|---|---|
| Registry integrity & memory | Hostile LAN host floods or forges ARP replies | Solicited-only replies (FR-DS-06), strict validation, per-scan response cap, registry cap 4,096, rate-limited sending |
| Terminal state | Escape/control sequences in hostnames or vendor strings | Type-level validated text (`Hostname`, `DisplayText`), ASCII-only hostnames, strip C0/C1/DEL/bidi controls |
| Parsers | Malformed packets/DNS/`/proc` content | Total parsers (no panics), no indexing panics, property tests + fuzzing |
| Host privileges | Capability abuse | ADR-005: drop caps after socket open, `no_new_privs`, group-restricted binary, no setuid |
| Device privacy | MACs/hostnames leaking to logs or outside | No network egress beyond §2.3, no logs by default, `0600` debug log with warning, ADR-003 |
| Third parties | Tool used on a network without authorization | Notice, local-subnet-only scope, public-range confirmation, bounded rate, no port scanning; documented that misuse cannot be technically prevented |
| User trust | Misleading claims | Controlled vocabulary (§5.4), honest limitation text, "observed ≠ verified" statement in Help/Details |
| Supply chain | Malicious/abandoned dependency | Minimal deps, approval process (§9), `cargo audit`, `cargo deny`, committed `Cargo.lock`, pinned CI actions |

### 7.2 Requirements
| ID | Requirement |
|---|---|
| SR-01 | `#![forbid(unsafe_code)]` in the package. Any dependency using `unsafe` is reviewed under §9.2. |
| SR-02 | No panics reachable from external input; `clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `todo`, `dbg_macro` denied outside tests. |
| SR-03 | No `println!`/`eprintln!` while the TUI is active (denied by lint; allowed only in `main.rs` before init / after restore). |
| SR-04 | All network- or file-derived text is validated at construction (FR-EN-04). |
| SR-05 | ARP and DNS parsers are fuzzed (`cargo-fuzz`) and property-tested; corpus committed. |
| SR-06 | Privilege drop is verified by test (CapEff/CapPrm = 0 after socket open). |
| SR-07 | No network traffic other than §2.3; verified in netns tests by capturing and asserting on egress. |
| SR-08 | Default run writes no logs and no files other than the notice acknowledgment. |
| SR-09 | `--debug-log` creates the file with mode `0600`, refuses to follow symlinks, and warns that it may contain device identifiers. |
| SR-10 | Reads of `/proc` and `/etc/resolv.conf` are size-bounded and tolerate any content. |
| SR-11 | `cargo audit` and `cargo deny` pass in CI; `Cargo.lock` committed. |
| SR-12 | Non-private subnet requires explicit confirmation (FR-SC-07). |
| SR-13 | Statement in Help and Details: "Information shown is observed on the network and has not been verified. ARP is not authenticated." |

---

## 8. Architecture

### 8.1 Layout (suggested; create modules only when their task arrives)
```text
osza-netmon/
├── plan.md  AGENTS.md  README.md  Cargo.toml  Cargo.lock  rust-toolchain.toml  deny.toml
├── docs/            adr/  reports/  poc/  usage.md  permissions.md  limitations.md  architecture.md  test-matrix.md
├── data/oui/        compact vendor DB + SOURCE.md (URLs, dates, SHA-256 of inputs)
├── examples/        poc_discover.rs  gen_oui.rs
├── fuzz/            arp_frame.rs  dns_response.rs  proc_parsers.rs   (separate package)
├── tests/           integration + netns scenarios
└── src/
    ├── main.rs                       # thin: args, wiring, terminal lifecycle
    ├── lib.rs
    ├── config.rs  clock.rs  error.rs
    ├── model/       mac.rs  text.rs  field.rs  device.rs  scope.rs  time.rs
    ├── registry/    mod.rs                              # aging, identity, tags, caps
    ├── discovery/   interface.rs  route.rs  neighbor_table.rs  privilege.rs
    │                arp/{codec.rs, scanner.rs, transport.rs}  scheduler.rs  worker.rs
    ├── enrichment/  vendor.rs  hostname.rs  dns.rs  worker.rs
    ├── app/         state.rs  action.rs  event.rs  update.rs   # model-update-view core
    └── ui/          lifecycle.rs  dashboard.rs  details.rs  scope.rs  notice.rs  help.rs
                     controls.rs  theme.rs  text.rs                # all user-facing strings in text.rs
```

### 8.2 Dependency rules (enforced in review)
| Module | May depend on |
|---|---|
| `model`, `clock` | std only (+ `thiserror`) |
| `registry` | `model`, `clock` |
| `discovery` | `model`, `clock` — **not** `registry`, `app`, `ui` |
| `enrichment` | `model` — **not** `registry`, `app`, `ui` |
| `app` | `model`, `registry`, event/command *types* of `discovery` and `enrichment`, `config` |
| `ui` | `app` state (read-only views), `model` — **no I/O, no calls into workers** |
| `main` | everything (wiring only) |

### 8.3 Threads and channels (ADR-012)
```text
 [Input thread]──┐                      ┌─► [Discovery worker]  (owns raw socket, neighbor reads)
                 ▼                      │       ▲ commands (bounded, small)
 [Enrichment]──► AppEvent queue ──► [Main thread: App state + Registry + UI]
   worker         (bounded)             │       ▼ commands (bounded, small)
                                        └─► [Enrichment worker]  (DNS PTR; vendor is in-process)
```
- **One** bounded `AppEvent` queue feeds the main loop (input, tick, discovery, enrichment). The main loop blocks on `recv_timeout(next_deadline)` — no busy polling — then drains at most N further events per iteration so rendering is never starved.
- Workers batch observations (≤ every 50 ms) so queue pressure stays low.
- A worker whose send would block MUST keep checking its cancel flag (no uninterruptible blocking). No unbounded channels anywhere.
- The input thread uses `crossterm` `poll` with a short timeout and a stop flag so it can shut down cleanly.
- Scan results carry a `ScanId`; the registry ignores results of superseded or cancelled scans.

### 8.4 Event loop (normative behavior)
```text
loop:
  if dirty: render
  wait = min(time_to_next_deadline, MAX_WAIT)
  ev = recv_timeout(wait)
  handle(ev); drain up to N more events
  scheduler.poll(now) -> maybe StartScan          # never while a scan is running
```
`update(state, event) -> (state', effects)` is a pure function wherever practical; `effects` (start scan, queue lookups, quit) are executed by `main`. This makes the whole application scriptable in tests without a terminal or network.

### 8.5 Scan lifecycle
```text
StartScan(id, scope, passes) ─► registry.begin_cycle(id)
  1. read neighbor table  ─► Observation* (NeighborTable)
  2. for pass in 1..=passes:  send paced ARP requests (pass 2: only non-responders)
                              listen concurrently; solicited valid replies ─► Observation* (ArpReply)
  3. listen window elapses
  4. read neighbor table  ─► Observation*
  5. ScanFinished(id, outcome) ─► registry.end_cycle(id, outcome)   # ages absent devices if Complete
```

### 8.6 Trait boundaries (illustrative)
```rust
trait Clock          { fn now(&self) -> Timestamp; }
trait NeighborSource { fn read(&self, iface: &InterfaceInfo) -> Result<Vec<RawNeighbor>, NeighborError>; }
trait ArpTransport   { fn send_request(&mut self, target: Ipv4Addr) -> Result<(), TransportError>;
                       fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError>; }
trait NameResolver   { fn reverse(&self, ip: Ipv4Addr, deadline: Duration) -> Result<Option<Hostname>, ResolveError>; }
```
Production implementations touch the OS; test implementations are in-memory and deterministic.

### 8.7 Error handling
`thiserror` enums per module. Only `main` may convert into a top-level error type. No error is swallowed silently: it is either handled, mapped to a `UserMessage {what, why, action}`, or propagated.

### 8.8 Terminal lifecycle
- `ratatui::init()`/`try_init()` installs a panic hook that restores the terminal (verified against the ratatui 0.30 documentation; its docs say to install any other hooks **before** init). Pin the exact ratatui version at T-000 and re-verify on upgrade.
- Mouse capture is **not** enabled or disabled by `init()`/`restore()`; the app enables it explicitly (unless `--no-mouse`) and an RAII guard disables it on every exit path.
- Use the crossterm re-export from ratatui to avoid duplicate crossterm versions.
- `Ctrl+C` arrives as a key event in raw mode and MUST be handled as quit.
- SIGTERM/SIGHUP MUST also restore the terminal (candidate: `signal-hook`, decided in T-301).
- A `Drop` guard is the final safety net; a test asserts the terminal state after normal exit and after a forced panic.

### 8.9 Time display
Tables and header use relative ages (`8s ago`, `3m ago`). Details show absolute local time `HH:MM:SS` computed with a small, well-maintained time crate (candidates `chrono`/`jiff`, decided in T-304) — or UTC clearly labeled if no crate is justified.

---

## 9. Dependency Policy

### 9.1 Classification
| Class | Crates | Rule |
|---|---|---|
| **Approved** | `ratatui` (pin exact version; latest at plan time is 0.30.x), `thiserror` | Use freely. |
| **Candidates** (decision by ADR in the named task) | transport: `pnet_datalink` / `nix` / `socket2` (T-105) · capabilities: `caps` / `capctl` (T-104) · DNS wire format: `simple-dns` / `hickory-proto` (T-203) · signals: `signal-hook` (T-301) · args: `lexopt` / `pico-args` / `clap` (T-402) · time: `chrono` / `jiff` (T-304) | Evaluate against §9.2 in the report; Manager approves. |
| **Dev-only candidates** | `proptest`, `insta`, `csv` (for `gen_oui`), `cargo-fuzz`/`arbitrary` | Allowed in dev-dependencies after a one-line justification. |
| **Prohibited in MVP** | async runtimes (tokio, async-std); HTTP/TLS clients or anything with network egress; telemetry/analytics; `openssl`; libpcap bindings; crates needing network access at build time; Nmap wrappers | Needs a plan change. |
| **Everything else** | — | Not allowed until approved through a Plan Question. |

### 9.2 Evaluation criteria (copy into the report when proposing a crate)
1. Necessity: what is the smallest alternative (std, 30 lines of our code)?
2. Maintenance: last release date, open advisories (`cargo audit`), issue health.
3. License compatible with `deny.toml` allowlist (MIT/Apache-2.0/BSD/ISC/Unicode).
4. `unsafe` footprint and what it wraps.
5. Transitive dependency count and build-time cost; no async runtime pulled in.
6. MSRV compatible with our pinned toolchain.
7. Works with our constraints: no network at runtime, no build scripts that fetch data.

---

## 10. UI Specification

### 10.1 Screens and flow
```text
[Notice (first run / version change)] ─y─► [Scope selection + confirmation] ─Enter─► [Dashboard] ◄──Esc── [Details]
                                                                                  │  ?                      ▲
                                                                                  └──► [Help overlay]       └── Enter
Any screen: q / Ctrl+C = quit.   Terminal < 80×24 = "Too small" screen.
```

### 10.2 Wireframes (illustrative; exact glyphs and widths are finalized in T-303 via snapshot review)

**Notice**
```text
 osza Network Monitor — Authorization notice
 ─────────────────────────────────────────────────────────────
 This tool is intended only for networks you own or are
 explicitly authorized to monitor. Local discovery sends
 network probes. Use this tool only within an authorized network.

 It does not scan ports, capture traffic, or send device
 information to any external service.

 [y] I understand and continue      [q] Quit
```

**Scope selection**
```text
 Choose the network to monitor                 Authorized networks only.
 > wlan0    192.168.1.20/24   Wi-Fi     gateway 192.168.1.1   suggested
   eth0     —                 unavailable: no IPv4 address
   docker0  172.17.0.1/16     virtual
 Mode: active — will send 253 ARP requests (about 3 s) on 192.168.1.0/24
 [Enter] Confirm   [↑/↓] Choose   [q] Quit
```

**Dashboard**
```text
 osza Network Monitor 0.1.0            Authorized networks only
 Interface wlan0   Network 192.168.1.0/24   Mode active
 Last scan: complete 8s ago · next in 52s   Devices 14 (12 recent, 2 idle)
┌ Devices ─────────────────────────────────────────────────────────────────────┐
│ Hostname       IPv4 ▲         MAC                Vendor        Status Seen     │
│ router.lan [gw]192.168.1.1    a4:2b:b0:11:22:33  ExampleCo     Recent 8s ago   │
│ Unknown [you]  192.168.1.20   dc:a6:32:aa:bb:cc  ExampleLtd    Recent 8s ago   │
│ Unknown        192.168.1.34   3e:5f:12:9a:00:01  Private addr.  Idle   4m ago   │
└──────────────────────────────────────────────────────────────────────────────┘
 [Enter] Details  [r] Refresh  [s] Sort  [?] Help  [q] Quit       status/error msg
```

**Details**
```text
 Device details                                                     [Esc] Back
 ── Identity ───────────────────────────────────────────────
 Hostname     router.lan   (reverse DNS via 192.168.1.1)
 IPv4         192.168.1.1  (other IPs seen: none)
 MAC          a4:2b:b0:11:22:33
 Vendor       ExampleCo   (offline IEEE database, 2026-10-01)      Tags: Gateway
 ── Observation ────────────────────────────────────────────
 First observed   14:02:11 (this session)
 Last observed    14:16:40 (8 s ago)
 Status           Recent — observed in the latest scan cycle
 Interface        wlan0
 ── Information sources ────────────────────────────────────
 IPv4/MAC   ARP reply, neighbor table      Hostname   reverse DNS
 Not determined: none
 Note: information is observed on the network and has not been verified.
```
When data is missing the same rows show `Unknown`, `Unavailable (no local resolver)`, or `…`, plus any relevant discovery error or limitation.

### 10.3 Keyboard map (mandatory)
| Key | Action |
|---|---|
| `↑` / `↓`, `j` / `k` | Move selection |
| `PgUp` / `PgDn`, `Home` / `End`, `g` / `G` | Page / jump |
| `Enter` | Open details (dashboard); confirm (scope screen) |
| `r` | Refresh now |
| `s` | Cycle sort: IPv4 ↔ hostname |
| `Esc` | Back / close overlay |
| `?` | Help |
| `q`, `Ctrl+C` | Quit from any screen (except while typing a `yes` confirmation, where `Esc` cancels) |

### 10.4 Content rules
- Table columns: Hostname, IPv4, MAC, Vendor, Status, Last seen. At 80 columns: fixed widths for IPv4 (15), MAC (17), Status (6), Seen (8); Hostname and Vendor share the remainder with ellipsis; tags remain visible without hiding a mandatory column (final layout in T-303).
- Header always shows: name+version, reminder, interface, subnet, mode, last-scan outcome and age, next scan, device counts.
- Details: Identity, Observation, Information sources (mandatory); neutral notes (shared-MAC, IP seen under another MAC) when applicable; the SR-13 statement.
- Strings live in `ui/text.rs`, in English; localization is out of scope but this keeps it feasible. RTL/Arabic UI is a post-MVP consideration, not a 0.1.0 requirement.

### 10.5 Mouse (enhancement)
Left-click on an action-bar control activates it; click on a row selects it; clicking the selected row opens Details; wheel scrolls. Hit regions are derived from the same layout rectangles used for rendering. Mouse capture can be disabled with `--no-mouse`; docs note that capture changes text selection (use Shift+drag in most terminals). Every mouse action has a keyboard equivalent.

### 10.6 Colors (never the only signal)
Cyan/blue = selection and active controls · Green = Recent · Yellow = Idle, incomplete or degraded mode · Red = application or discovery error · Dim gray = Unknown/Unavailable. `NO_COLOR` disables color; labels and symbols (`▲` sort marker, text status words) still carry all meaning. An unfamiliar device is never colored as a warning.

---

## 11. Quality and Testing Strategy

### 11.1 Test layers
| Layer | What | Tools |
|---|---|---|
| Unit | MAC/IP parsing & formatting, scope math, sanitization, vendor longest-prefix, registry merge/aging, status transitions, tags, caps, sorting, scheduler state machine, error mapping | built-in tests with `FakeClock` |
| Property | Parsers never panic and round-trip; registry invariants (no duplicate keys, monotonic timestamps, selection stable) | `proptest` |
| Fuzz | ARP frame parser, DNS response parser, `/proc` parsers, resolv.conf parser | `cargo-fuzz` (smoke run in CI, longer scheduled run) |
| Component | Scanner with a fake `ArpTransport` (pacing, passes, solicited-only, cancel, outcomes); app `update()` scenario scripts | in-memory fakes |
| UI | Rendering at several sizes (80×24, 100×30, 120×40, tiny), states (empty, scanning, errors, read-only, many devices), keyboard and mouse flows, resize, terminal restore | ratatui `TestBackend` + `insta` snapshots |
| Integration | Real raw-socket discovery inside Linux network namespaces with veth pairs | `ip netns`, scripted; see §11.2 |
| Manual acceptance | The Owner's real network (client-isolated Wi-Fi: the limited-visibility case) plus any additional authorized networks that become available | `docs/test-matrix.md` (Appendix D) |

### 11.2 Network namespace scenarios (T-106)
The kernel answers ARP for any address configured on the peer interface, so many "devices" are just addresses in a peer namespace.
- **S1** 20 responding addresses → all discovered, none duplicated.
- **S2** 250 addresses → completes within NFR-02, packet count = passes × hosts at the configured rate.
- **S3** silent addresses (non-responders) → scan completes, no hang.
- **S4** proxy ARP (`proxy_arp=1` on a router namespace) → one MAC with many IPs → `Multiple IPs`, not merged with others.
- **S5** hostile frames (helper tool): unsolicited replies, malformed lengths, multicast sender MAC, out-of-scope sender IP, flood → rejected; registry cap holds.
- **S6** egress assertion: captured traffic contains only ARP requests (+ allowed DNS PTR) — SR-07.
- **S7** no privilege → read-only mode with correct message; after privileged start, `CapEff`/`CapPrm` are zero — SR-06.
- **S8** impairment profiles P0–P3 (Appendix D) applied to S1/S2: recall per cycle is measured and compared with the G-1 thresholds. Loss, delay and jitter use `tc netem` where the kernel module is available; otherwise the helper responder drops or delays replies itself.
- **S9** "sleepy hosts": addresses served by a helper responder (not configured on the kernel) that ignores the first N requests, answers only a fraction, or answers late, emulating power-save Wi-Fi clients. Reported, not gated.
CI may need `sudo`/unprivileged user namespaces for these; they run behind `OSZA_NETNS_TESTS=1` and in a dedicated CI job.

### 11.3 Engineering gates (every change)
`cargo fmt --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all-features` · `cargo doc --no-deps` (no warnings) · `cargo audit` · `cargo deny check`. MSRV build check. `Cargo.toml` `[lints]`: `unsafe_code = "forbid"`; clippy `unwrap_used`, `indexing_slicing`, `panic`, `todo`, `dbg_macro`, `print_stdout`, `print_stderr` denied outside tests (scoped allow in `main.rs`).

### 11.4 Test-quality rules
- Each new behavior ships with tests that fail without it. Tests assert behavior, not implementation details.
- No `sleep`-based timing in unit tests; use the injected clock.
- A test is never weakened, ignored or deleted to make a change pass without a Plan Question.
- Snapshot changes require the reviewer to inspect the diff, not just accept it.

### 11.5 Performance verification (T-403)
Measure NFR-01…NFR-07 on the reference machine and report numbers, method and variance. Include an idle 60 s CPU/wake-up measurement and a 1,000-device RSS measurement (synthetic registry fill).

### 11.6 Documentation as a testable artifact
`docs/limitations.md` MUST state that the list may be incomplete and why (client isolation, sleeping devices, AP behavior, segmentation, permissions). The reviewer checks that no document claims completeness (AC-14).

### 11.7 Automated vocabulary check
A test (or CI grep) scans `src/ui/` and `docs/` for the banned words in §5.4 and fails on a match outside an allow-listed "never use" table.

---

## 12. Roadmap, Phases and Gates

Effort sizes are relative: **S** small · **M** medium · **L** large. No calendar estimates are made until the PoC provides evidence.

```text
Phase 0  Foundations ──► G-0
Phase 1  Technical PoC (no TUI) ──► G-1  (go / adjust / stop decision)
Phase 2  Core: registry, enrichment, orchestration, app core ──► G-2
Phase 3  TUI ──► G-3
Phase 4  Reliability, hardening, packaging, acceptance ──► G-4 = MVP 0.1.0
```

### 12.1 Dependency graph
| Task | Depends on | Can run in parallel with |
|---|---|---|
| T-000 | — | — |
| T-001 | T-000 | T-002 |
| T-002 | T-000 | T-001 |
| T-101, T-102, T-103 | T-002 | each other, T-202, T-203 |
| T-104 | T-101, T-103 | T-202, T-203 |
| T-106 | T-104 | T-202, T-203 |
| T-105 | T-102, T-104, T-106 | T-202, T-203 |
| **G-1** | T-101…T-106 | |
| T-201 | G-1, T-002 | T-202, T-203 |
| T-202, T-203 | T-002 (T-203 also needs T-101 for scope) | T-201 |
| T-204 | T-104, T-102, T-201 | T-202, T-203 |
| T-205 | T-201, T-203, T-204, T-202 | — |
| **G-2** | T-201…T-205 | |
| T-301 | T-000 (can start earlier with a stub app) | T-205 |
| T-302, T-303, T-304 | T-205, T-301 | each other (shared `theme.rs`: coordinate) |
| T-305 | T-303 | T-304 |
| T-306 | T-302…T-305 | — |
| **G-3** | T-301…T-306 | |
| T-401, T-402 | G-3 | each other |
| T-403, T-404 | T-401, T-402 | each other |
| T-405 | T-401…T-404 | — |
| T-406 | T-405 | — |
| **G-4** | T-401…T-406 | |

### 12.2 Gates (Manager decides; each requires the reports and reviews of its tasks)
| Gate | Pass criteria |
|---|---|
| **G-0** | Repo builds, CI gates green, lints in force, ADRs 001–008, 012, 013, 014, 016 recorded, core primitives tested including sanitization. |
| **G-1** | Discovery works without the TUI in network namespaces and on the Owner's real (client-isolated) network. **Validation environment (Owner decision, v1.1.0):** the Owner's real Wi-Fi isolates clients and cannot provide ground truth, so recall is measured on **synthetic networks** (T-106) under the impairment profiles of Appendix D. **Success metric:** ≥ 95% recall within 3 cycles on profiles P0–P2 for scenarios S1, S2 and S4 (S9 "sleepy hosts" is reported separately with its observed recall). **Stop/adjust trigger:** < 95% on P0–P2 after tuning (ADR-011 options exhausted) → Manager adjusts the strategy or escalates to the Owner. On the Owner's isolated network near-zero visibility is **not** a failure: the run must complete cleanly, the neighbor-table path and the honest limited-visibility UX are verified, and the observation is recorded. **Declared gap:** behavior on real wired LANs and non-isolated Wi-Fi is not validated by the project (R-15); this is stated in the PoC report and in `docs/limitations.md`. ADR-009/010/011 decided. Permission model verified (SR-06). Limitation catalog written. |
| **G-2** | Headless app core passes scenario tests driving discovery fakes and the real netns scanner; registry invariants proven; vendor DB and hostname enrichment verified; NFR-03 satisfied in headless benchmarks. |
| **G-3** | A person can: notice → scope → discover → browse → details → refresh → quit, with keyboard and mouse; snapshots reviewed; terminal restore verified; no blocking during scans. |
| **G-4** | All AC-01…AC-17 met with evidence (§19); NFRs measured; security hardening complete; docs complete, including the validation-scope statement in `docs/limitations.md`; acceptance campaign (Appendix D) signed by the Owner. |

---

## 13. Task Catalog

Authoritative scope summaries. The Manager issues a full task card (Appendix A) for each task, one at a time, including any adjustments from earlier reports. Each task ends with an Execution Report (Appendix B) and a Review (Appendix C).

### Phase 0 — Foundations

**T-000 Repository bootstrap** · M · *Implements: SR-01, SR-02, SR-03, SR-11, §11.3*
- Cargo package `osza-netmon` (lib + bin), latest stable edition supported by a pinned toolchain; `rust-toolchain.toml`; `Cargo.lock` committed; `[lints]` and release profile (`lto="thin"`, `codegen-units=1`, `strip`, `panic="unwind"`).
- `deny.toml`, `rustfmt.toml` (minimal), `.gitignore`, `README.md` stub, `AGENTS.md` (Appendix F), `docs/` skeleton, `plan.md` at the root, CI workflow running all §11.3 gates. License per ADR-014: verbatim GPL-3.0 `LICENSE`, `license = "GPL-3.0-only"`, SPDX header on every `.rs` file (CI-enforced), `publish = false`; `deny.toml` license allowlist limited to GPL-3.0-compatible licenses and bans the §9.1 prohibited crates.
- **Acceptance:** fresh clone builds; all gates pass in CI; `--version` prints name/version; a deliberate `unsafe` block, `unwrap()` or `println!` in a scratch commit is rejected by the gates; exact ratatui version pinned and recorded.

**T-001 ADR records** · S · *Depends: T-000*
- Transcribe §4 into `docs/adr/NNNN-title.md` using Appendix G, with correct statuses and an index.
- **Acceptance:** one file per ADR, consistent with §4; Pending/Open ones list their deciding task.

**T-002 Core primitives** · M · *Implements: FR-EN-04, SR-04, §5.2–5.3*
- `MacAddr` (parse `aa:bb:..` / `aa-bb-..` / `aabb..`; canonical lowercase colon display; multicast/broadcast/zero/locally-administered predicates).
- `Hostname` (ASCII `[A-Za-z0-9._-]`, ≤ 253, validating constructor only) and `DisplayText` (strips C0/C1/DEL, bidi-control and zero-width characters; collapses whitespace; truncates to 64 chars).
- `Field<T>`, `Source`, `Timestamp`, `Clock` + `SystemClock` + `FakeClock`; IPv4 helpers: private/link-local/CGNAT classification, own small `Ipv4Net` (host range math incl. /30, /31, /32, over-cap).
- **Acceptance:** round-trip and rejection tests; sanitization tests with ANSI escape sequences, OSC, bidi overrides, C1 controls, very long and empty input; property tests (never panic, parse∘format = identity); classification table tests.

### Phase 1 — Technical Proof of Concept

**T-101 Interfaces, scope, default route** · M · *Implements: FR-SC-01…05*
- `InterfaceInfo`, eligibility with reasons, ranking, suggestion; pure parser for `/proc/net/route` (little-endian hex) to find the default gateway per interface; scope derivation incl. host counts and cap handling.
- Interface data source chosen per §9.2 and reported (e.g., `getifaddrs` via a safe wrapper, `/sys/class/net`).
- **Acceptance:** fixture-driven tests for route parsing (multiple routes, no default, malformed lines); ranking tests (Wi-Fi + docker + veth + lo); scope math tests for /24, /22, /30, /31, /32, /16 (over cap).

**T-102 Neighbor table reader** · S · *Implements: FR-DS-01, FR-DS-02, SR-10*
- `NeighborSource` trait; `/proc/net/arp` parser (columns IP, HW type, Flags, HW address, Mask, Device); filters per FR-DS-02; size-bounded read; tolerant of any content.
- **Acceptance:** fixtures with complete/incomplete (flags `0x0`), permanent, wrong-interface, zero-MAC and garbage lines; fuzz target `proc_parsers`.

**T-103 ARP codec** · M · *Implements: FR-DS-03, FR-DS-06, SR-05*
- Build a 42-byte Ethernet+ARP request; parse and validate replies exactly per FR-DS-06 with a total (non-panicking) parser; own fixed-layout implementation unless ADR-009 chooses a library parser.
- **Acceptance:** golden vectors; negative vectors for every FR-DS-06 clause (truncated, wrong htype/ptype/hlen/plen/opcode, MAC mismatch, multicast/zero/broadcast sender, wrong destination); property tests; fuzz target `arp_frame`.

**T-104 ARP scanner and privilege handling** · L · *Implements: FR-DS-03…11, ADR-005*
- `ArpTransport` trait + production implementation (library per ADR-009 evidence; interim choice allowed, behind the trait); sweep engine: target generation, pacing, passes (non-responders only on pass 2), concurrent listen, solicited-only table, per-scan response cap, listen window, cancellation ≤ 250 ms, outcome classification.
- Privilege: open socket bound to interface + `ETH_P_ARP`; map `EPERM` to a typed error; drop capabilities and set `no_new_privs`; self-verification of `CapEff`/`CapPrm`.
- `examples/poc_discover.rs`: prints observations and a summary with counters (no TUI).
- **Acceptance:** fake-transport tests for every behavior above using the fake clock; manual run in an authorized lab shows discovered devices; capability-drop test passes; no `unsafe` in our code.

**T-105 PoC measurement campaign and decision report** · M · *Mostly agent-run in netns; one human-run observation on the Owner's isolated network; protocol in Appendix D*
- Run the protocol on the synthetic networks (netns profiles P0–P3) and on the Owner's isolated Wi-Fi (observation only); compare transports (criteria §9.2), neighbor sources, probe strategies (rate, passes, sender IP `0.0.0.0` vs interface IP, unicast refresh of known devices).
- Deliver `docs/poc/poc-report.md` with raw data, recall per cycle, timings, packet counts, failure cases; proposed ADR-009/010/011; limitation catalog; go / adjust / stop recommendation against G-1.
- **Acceptance:** every Appendix D metric reported with method; recommendations justified by data, not preference.

**T-106 Network-namespace integration harness** · M · *Implements: §11.2*
- Scripts and Rust integration tests for S1–S9 behind `OSZA_NETNS_TESTS=1`; dev-only helper for hostile frames and for sleepy/impaired responders; impairment profiles P0–P3; CI job (privileges documented).
- **Acceptance:** S1–S7 pass locally and in CI (or CI limitation documented with the local procedure); S6 asserts egress contents; S8/S9 produce the recall tables required by G-1 and T-105.

### Phase 2 — Core

**T-201 Device registry** · L · *Implements: FR-RG-01…07, ADR-007, ADR-008*
- Registry with `begin_cycle/observe/end_cycle`, identity, IP history, Recent/Idle aging, tags (`This device`, `Gateway`, `Private address`, `Multiple IPs`), IP-conflict note, cap with warning state, stable sorting, selection by `DeviceKey`.
- **Acceptance:** tests for every ADR-007/008 rule (3-cycle + age-floor transitions, partial/failed cycles don't age, refresh spam doesn't idle, shared-MAC threshold, cap behavior, stale `ScanId` ignored); property tests for invariants; no `sleep`.

**T-202 Vendor database** · M · *Implements: FR-EN-01, FR-EN-02*
- `examples/gen_oui.rs` converts IEEE MA-L/MA-M/MA-S (and legacy IAB if distributed separately) CSVs to a compact sorted binary or text format in `data/oui/` with `SOURCE.md` (URLs, retrieval date, SHA-256). Redistribution terms of the IEEE data are checked and recorded. Runtime: embedded data, longest-prefix lookup (36 → 28 → 24 bits), names sanitized via `DisplayText`.
- **Acceptance:** tests with known MA-L, MA-M, MA-S samples and overlapping-prefix cases; missing vendor → `Unknown`; locally-administered → `Private address`; DB date exposed; size reported.

**T-203 Hostname resolver** · M · *Implements: FR-EN-03, ADR-003, ADR-015*
- Resolver-selection logic (resolv.conf + systemd-resolved file, subnet rule), PTR query/response via the DNS crate chosen under §9.2, worker thread with bounded queue, timeout/retry/backoff, validation into `Hostname`, `--no-hostnames`.
- **Acceptance:** tests for resolver eligibility (stub excluded, off-subnet excluded, none eligible → `Unavailable`), hostile responses (oversize, compression loops, invalid characters, wrong ID/question), fuzz target `dns_response`; local fake DNS server integration test; no query leaves to non-eligible servers.

**T-204 Discovery orchestrator and scheduler** · M · *Implements: FR-DS-08…12, FR-DS-14, §8.3*
- Discovery worker thread: commands/events, `ScanId`, batching, cancellation, read-only mode, scheduler state machine (interval after finish, failure backoff, stop after 3 failures, manual refresh rules).
- **Acceptance:** scheduler is a pure state machine with table-driven tests; worker tested with fake sources/transport; channel bounds and cancel-under-backpressure tested.

**T-205 Application core (headless)** · L · *Implements: §8.4*
- `AppState`, `Action`, `AppEvent`, pure `update()`, effects executor in `main`/app wiring, screen state machine (Notice → Scope → Dashboard/Details/Help), message log (last 20), counters; hostname/vendor enrichment integration.
- **Acceptance:** scenario scripts drive the whole flow headlessly (including errors, read-only, resize events, quit); NFR-03 benchmark with 4,096 devices and event bursts.

### Phase 3 — TUI

**T-301 Terminal lifecycle and event loop** · M · *Implements: FR-UI-06, FR-UI-07, §8.8*
- `ratatui::init()` + RAII guard; explicit mouse capture enable/disable; resize; input thread; `recv_timeout` loop with dirty-flag rendering and 1 Hz tick; Ctrl+C; SIGTERM/SIGHUP handling (library per §9.2); panic-safety test.
- **Acceptance:** terminal restored after normal exit, error exit, forced panic and signals (tested in a pty); idle CPU target met.

**T-302 Notice, scope and too-small screens** · M · *Implements: FR-ST-01…04, FR-SC-01…08*
- Notice with ack persistence (`0600`, non-fatal failures), scope list with reasons, request count/duration, large-scope and public-range confirmations, `--interface` preselect.
- **Acceptance:** snapshot and flow tests; no probe before ack+confirm (asserted via fake discovery); ack file permissions tested.

**T-303 Dashboard** · L · *Implements: FR-UI-01, FR-UI-05, FR-RG-06, §10.4, §10.6*
- Header, table, action bar, sorting indicator, selection by key, scrolling, status/tag rendering, `NO_COLOR`, degraded-mode banners, error line.
- **Acceptance:** snapshots at 80×24/100×30/120×40, empty/scanning/many-devices/errors/read-only states; selection survives refresh and re-sort; column rules satisfied at 80 columns.

**T-304 Details and help screens** · M · *Implements: FR-UI-02, FR-UI-03, §10.2, §8.9*
- Details sections, neutral notes, SR-13 statement, back with preserved selection; help (keys, vocabulary, limitations, DB date, resolver policy, recent messages); time display decision.
- **Acceptance:** snapshots for complete and sparse records; missing fields explicit; Back preserves registry and selection; vocabulary check passes.

**T-305 Mouse support** · S · *Implements: §10.5*
- Hit-testing from layout rectangles, clickable action bar, row select / reselect-to-open, wheel scroll, `--no-mouse`.
- **Acceptance:** event-driven tests for each click target; keyboard parity verified; mouse capture disabled on every exit path.

**T-306 UI test suite** · M · *Implements: §11.1 UI layer*
- Consolidate snapshots and flow tests, resize storms, terminal-too-small transitions, restore tests, vocabulary check wiring.
- **Acceptance:** suite is deterministic; snapshot review notes in the report.

### Phase 4 — Reliability and release

**T-401 Errors and degraded-mode UX** · M · *Implements: §6.8*
- Complete the error taxonomy with `what/why/action` messages, read-only guidance, interface-loss and resolver messages, registry-cap warning, message de-duplication.
- **Acceptance:** each row of §6.8 has a test; messages reviewed against §5.4.

**T-402 CLI** · S · *Implements: §6.7*
- Flag parsing, validation and help text; argument parser chosen per §9.2.
- **Acceptance:** tests for valid/invalid combinations; out-of-range values rejected with clear messages; `--max-hosts` ceiling enforced.

**T-403 Performance and resource verification** · M · *Implements: NFR-01…07, NFR-10*
- Measure per §11.5; fix regressions found.
- **Acceptance:** all budgets met or deviations accepted by the Manager in writing.

**T-404 Security hardening pass** · M · *Implements: SR-01…13*
- Walk the threat model (§7.1) item by item with evidence; long fuzz runs; verify no `unsafe`; audit/deny; privilege-drop and egress tests in CI; log-policy tests; dependency review.
- **Acceptance:** a signed-off checklist in the report mapping every SR to evidence; zero open Blocker/Major findings.

**T-405 Documentation and packaging** · M · *Needs O-7 resolved*
- `README.md`, `docs/usage.md` (one page, first-60-seconds flow), `docs/permissions.md` (including the `setcap` procedure, group restriction, read-only mode), `docs/limitations.md`, `SECURITY.md`, `docs/architecture.md`; reproducible release build, checksums, packaging script.
- **Acceptance:** a fresh machine can follow the docs to a working install; no document claims completeness (AC-14); vocabulary check passes.

**T-406 Acceptance campaign and release candidate** · M · *Human-run with executor support*
- Execute `docs/test-matrix.md` on the Owner's network (limited-visibility case) and the full netns suites; produce the AC traceability table with evidence and the validation-scope statement for `docs/limitations.md`.
- **Acceptance:** AC-01…AC-17 each marked Met with links to evidence; Owner sign-off.

---

## 14. Agent Operating Protocol

### 14.1 Roles
| Role | Responsibilities | Must not |
|---|---|---|
| **Owner** | Relays task cards to agents and reports back to the Manager; owns open decisions (§20); runs human-only steps (real-network tests); signs MVP acceptance. | — |
| **Manager** | Maintains this plan; writes task cards; reads Execution and Review Reports; issues the next order (accept / follow-up / rework / escalate); decides gates and ADRs. | Write production code; skip a review. |
| **Executor agent** | Implements exactly one task card; writes tests and docs required by it; produces an Execution Report. | Expand scope; add dependencies without approval; change `plan.md`; weaken tests. |
| **Reviewer agent** | Independently verifies the changeset against the task card and plan; re-runs commands; produces a Review Report. | Modify code (findings only; fixes go through a rework order). |

### 14.2 Task lifecycle
```text
TODO ─► ISSUED (task card) ─► IN PROGRESS ─► SUBMITTED (Execution Report)
     ─► IN REVIEW ─► REVIEWED (Review Report) ─► MANAGER DECISION ─┬─► DONE
                                                                  ├─► FOLLOW-UP TASKS created, then DONE
                                                                  ├─► REWORK ordered (back to IN PROGRESS)
                                                                  └─► BLOCKED / ESCALATED (Owner or plan change)
```
Rework is limited to **two** cycles; a third means the task card or plan is flawed and the Manager redesigns the task.

### 14.3 Working rules for every agent (mirrored in `AGENTS.md`)
1. Read the task card, then the plan sections it references. Do not rely on memory of other sections.
2. Do only what the card says. Anything useful but outside the card goes into "Suggested follow-ups".
3. Never silently deviate. A deviation is written in the report with justification, or becomes a Plan Question *before* you proceed if it affects behavior, scope, security, or dependencies.
4. No new dependencies without Manager approval (§9). No `unsafe`. No `println!`/`eprintln!` in TUI-reachable code.
5. All external input is hostile (P7). Parsers are total; no panics from external data.
6. Run all engineering gates (§11.3) before submitting and paste the results in the report.
7. Active network probing happens **only** in network namespaces or on networks the Owner has designated as authorized lab networks. Agents running in sandboxes use netns/fakes. Real-network runs are human-run steps.
8. Never put real MAC addresses, hostnames or private network details from the Owner's networks into the repository, fixtures or reports. Use synthetic data.
9. Commits: small and logical; message format `T-xxx: imperative summary`; one task = one branch `task/T-xxx-short-name` with a changeset the reviewer can read; never rewrite shared history.
10. If a gate fails for reasons unrelated to your change, report it; do not "fix" it silently.

### 14.4 How information flows
1. Manager writes a **task card** → Owner passes it to the Executor.
2. Executor delivers code + `docs/reports/T-xxx/execution-NN.md`; Owner passes the report to the Manager *and* triggers the Reviewer.
3. Reviewer delivers `docs/reports/T-xxx/review-NN.md`; Owner passes it to the Manager.
4. Manager answers with a **decision**: `ACCEPT`, `ACCEPT + FOLLOW-UPS (task cards attached)`, `REWORK (list of required changes)`, or `ESCALATE`, and updates the Status Board.
5. Gates: after the last task of a phase the Manager issues a **gate decision** (§12.2).

### 14.5 Plan Questions
A Plan Question is a short block in the report:
`PQ-n · Context · What the plan says (section) · Ambiguity/conflict · Options with consequences · Executor's recommendation · Blocking? (yes/no)`.
Blocking questions mean the agent stops that part of the work and reports immediately.

### 14.6 Severity scale (reviews)
| Severity | Meaning | Effect |
|---|---|---|
| **Blocker** | Violates a MUST, a security requirement or scope; crash/data corruption; acceptance criterion unmet; failing gate | Must fix |
| **Major** | Significant defect, missing test for a MUST, misleading UI/docs text | Must fix |
| **Minor** | Quality issue with limited impact | Fix or follow-up task |
| **Nit** | Style/preference | Optional |

### 14.7 Verdicts
`APPROVE` (no open Blocker/Major/Minor) · `APPROVE WITH FOLLOW-UPS` (only Minor/Nit) · `CHANGES REQUIRED` (any Blocker/Major) · `BLOCKED` (cannot review: missing info/environment).

### 14.8 Review checklist (applied to every task)
1. **Scope:** only what the card asked; none of §2.2; no banned probe types (§2.3).
2. **Acceptance criteria:** each re-verified independently (commands re-run, not trusted).
3. **Gates:** fmt, clippy `-D warnings`, tests, docs, audit, deny all pass.
4. **Security:** no `unsafe`, no panics on external input (SR-02), input validated at boundaries (SR-04), no secrets or real identifiers in fixtures, privilege handling as ADR-005.
5. **Architecture:** dependency rules (§8.2), single registry owner, UI does no I/O, bounded channels, cancellable waits.
6. **Honesty:** wording follows §5.4; no claim of completeness; unknown values explicit.
7. **Tests:** meaningful, deterministic, not weakened; edge cases from the card present.
8. **Dependencies:** none added without approval; Cargo.lock diff reviewed.
9. **Docs/ADR:** updated where behavior or decisions changed.
10. **Report accuracy:** the Execution Report matches what the diff actually does.

---

## 15. Definition of Done

**Task:** all acceptance criteria met and evidenced · gates pass · tests for new behavior · docs/ADRs updated · no unapproved dependency · no `unsafe`/`println!` violations · Execution Report complete · Review verdict `APPROVE` or `APPROVE WITH FOLLOW-UPS` · Manager decision recorded · Status Board updated.
**Phase:** its gate (§12.2) passed.
**MVP:** G-4 passed.

---

## 16. Release and Documentation Deliverables (0.1.0)

- Release binary for x86_64 and aarch64 (glibc), stripped, with SHA-256 checksums; reproducible build instructions (pinned toolchain + `Cargo.lock`); `--locked` builds.
- Docs: `README.md`, `docs/usage.md` (one page), `docs/permissions.md`, `docs/limitations.md`, `docs/architecture.md`, `docs/test-matrix.md`, `SECURITY.md` (how to report issues), license per ADR-014, data attribution in `data/oui/SOURCE.md`.
- `docs/permissions.md` MUST include: the exact `setcap` command, how to verify it, how to restrict execution by group, how to run read-only, what to do on `EPERM`, and why not to use `sudo`.
- `docs/limitations.md` MUST include: incomplete visibility (client isolation, sleeping devices, AP behavior, VLANs/segmentation), neighbor-table staleness, MAC randomization, proxy ARP, ARP being unauthenticated, hostname best-effort and DNS policy residual risk, vendor database age/meaning, Idle ≠ disconnected.

---

## 17. Risk Register

| ID | Risk | Impact | Mitigation | Owner |
|---|---|---|---|---|
| R-01 | ARP discovery is unreliable on some Wi-Fi networks (isolation, power-save) | Product perceived as broken | PoC evidence (G-1), multiple passes, neighbor-table merge, honest UX and docs, stop/adjust trigger | Manager |
| R-02 | Transport library unmaintained or awkward (`pnet` cadence) | Rework | `ArpTransport` trait isolates it; ADR-009 by evidence; alternatives evaluated | Executor/Manager |
| R-03 | Privilege setup is a usability barrier | Low adoption | Read-only fallback, clear `setcap` docs, actionable message | Manager |
| R-04 | OUI data licensing, size or staleness | Legal/accuracy | Check terms, record source and date, show DB date, regeneration tool | Executor |
| R-05 | Hostname lookup leaks or misleads | Privacy/trust | ADR-003, validation, `--no-hostnames`, honest labeling | Manager |
| R-06 | Scope creep | Delay, loss of identity | Scope gate (§1.2), banned list (§2.2), reviews check scope | Manager |
| R-07 | Agent drift or inconsistent output | Quality | Task cards, review checklist, ADRs, `AGENTS.md`, gate decisions | Manager |
| R-08 | netns tests unavailable in CI | Weak integration coverage | Local procedure documented; dedicated privileged job; fakes remain primary | Executor |
| R-09 | Terminal edge cases (tmux, SSH, odd terminals) | Corrupted shell | RAII guard, panic hook, signal handling, pty tests, manual matrix | Executor |
| R-10 | ratatui/crossterm API churn | Maintenance | Pin versions; UI isolated in `ui/` | Executor |
| R-11 | MAC randomization inflates device counts over time | Misread data | `Private address` label, limitation doc, no false merging | Manager |
| R-12 | Tool misuse on unauthorized networks | Legal/ethical | Notice, local-only scope, public-range confirmation, bounded rate, license disclaimer | Owner |
| R-13 | Dropping capabilities fails or is incomplete | Privilege retained | Verified by test (SR-06); `no_new_privs`; reviewed | Executor/Reviewer |
| R-14 | Relative-time/timezone dependency adds weight or unsoundness | Quality | Decision at T-304 with §9.2; UTC fallback | Executor |
| R-15 | Real-network validation gap: the Owner's only real network isolates Wi-Fi clients, so behavior on wired LANs and open Wi-Fi is unvalidated | Hidden real-world failures; overstated confidence | Synthetic impairment profiles (T-106), honest wording in docs and release notes ("validated on synthetic networks and one client-isolated Wi-Fi network"), invite community test reports, revisit when a wired or open network becomes available | Manager/Owner |

---

## 18. Post-MVP Backlog (not part of 0.1.0)

Entry rule: a feature must serve one of the four questions (§1.2) and receive its own ADR/task. Candidate order:
1. Device nicknames and "new since last session" markers (needs persistent storage — its own decision).
2. mDNS-based names to improve hostnames (a new probe class — requires plan change to §2.3).
3. Search/filter within the list.
4. Runtime interface/scope switching.
5. Netlink neighbor states if not adopted in 0.1.0.
6. Optional DHCP-lease hostname import from a router (explicit user action).
7. Seccomp hardening; static musl build.
8. Localization (including RTL considerations).

---

## 19. Traceability — Acceptance Criteria

| AC | Criterion | Verified by tasks |
|---|---|---|
| AC-01 | Starts and shows the authorization notice | T-302, T-306 |
| AC-02 | User can select/confirm interface and subnet | T-101, T-302 |
| AC-03 | Neighbor table and ARP results are combined | T-102, T-104, T-204, T-201 |
| AC-04 | Devices appear in a readable, ordered list | T-201, T-303 |
| AC-05 | IP, MAC, hostname, vendor shown correctly | T-202, T-203, T-303, T-304 |
| AC-06 | Missing/uncertain data is explicit | T-002, T-303, T-304 |
| AC-07 | Enter opens the selected device's details | T-304, T-306 |
| AC-08 | Refresh works; navigation never waits on a scan | T-204, T-205, T-301, T-403 |
| AC-09 | Idle distinguishable from Recent | T-201, T-303 |
| AC-10 | Failures and permission errors reported clearly | T-401, T-104 |
| AC-11 | No port scan, OS fingerprinting or threat detection | T-106 (S6), T-404, reviews |
| AC-12 | Terminal restored on exit | T-301, T-306 |
| AC-13 | Automated tests pass; documented discovery workflow verified on an authorized network (netns suites and the Owner's client-isolated Wi-Fi; see R-15) | T-106, T-406 |
| AC-14 | Docs never claim full visibility | T-405, §11.7 check |
| AC-15 | Missing privilege → read-only mode with actionable guidance | T-104, T-401 |
| AC-16 | Security hardening complete (fuzz, audit, privilege drop, validation) | T-404 |
| AC-17 | Performance budgets NFR-01…07 met | T-403 |

---

## 20. Open Items for the Owner

| # | Item | Status | Needed by | Default if unanswered |
|---|---|---|---|---|
| O-1 | Product name `osza-netmon` (ADR-001) | **Resolved** — confirmed | — | — |
| O-2 | License (ADR-014) | **Resolved** — GPL-3.0 (variant: see O-7) | — | — |
| O-3 | CI provider (ADR-016) | **Resolved** — GitHub Actions on `osza-tools/osza-netmon` | — | — |
| O-4 | Test networks | **Resolved** — the Owner's Wi-Fi isolates clients; validation uses synthetic netns networks (G-1, R-15). If a wired LAN port or non-isolated network becomes available later, the Owner shares it as an extra validation opportunity. | — | — |
| O-5 | Confirm target platforms/kernels (§3.4) | Open | T-000 | as stated in §3.4 |
| O-6 | Confirm first-run-only full notice (ADR-004) | Open | T-302 | as stated in ADR-004 |
| O-7 | `GPL-3.0-only` or `GPL-3.0-or-later` | Open | T-000 | `GPL-3.0-only` |
| O-8 | Repository settings (Owner action): protect `main` (require PR + passing CI), enable Dependabot/security alerts and private vulnerability reporting | Open | T-000 | recommended, not enforced |

---

## 21. Status Board

| Task | Title | Status | Last decision |
|---|---|---|---|
| T-000 | Repository bootstrap | TODO | — |
| T-001 | ADR records | TODO | — |
| T-002 | Core primitives | TODO | — |
| T-101 | Interfaces, scope, default route | TODO | — |
| T-102 | Neighbor table reader | TODO | — |
| T-103 | ARP codec | TODO | — |
| T-104 | ARP scanner and privilege handling | TODO | — |
| T-105 | PoC measurement and decision report | TODO | — |
| T-106 | netns integration harness | TODO | — |
| T-201 | Device registry | TODO | — |
| T-202 | Vendor database | TODO | — |
| T-203 | Hostname resolver | TODO | — |
| T-204 | Discovery orchestrator and scheduler | TODO | — |
| T-205 | Application core (headless) | TODO | — |
| T-301 | Terminal lifecycle and event loop | TODO | — |
| T-302 | Notice, scope, too-small screens | TODO | — |
| T-303 | Dashboard | TODO | — |
| T-304 | Details and help screens | TODO | — |
| T-305 | Mouse support | TODO | — |
| T-306 | UI test suite | TODO | — |
| T-401 | Errors and degraded-mode UX | TODO | — |
| T-402 | CLI | TODO | — |
| T-403 | Performance verification | TODO | — |
| T-404 | Security hardening pass | TODO | — |
| T-405 | Documentation and packaging | TODO | — |
| T-406 | Acceptance campaign | TODO | — |

Gates: G-0 ☐ · G-1 ☐ · G-2 ☐ · G-3 ☐ · G-4 ☐

---

## 22. Changelog

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-10-26 | Initial plan derived from the Project Brief v0.1.0 and the Manager's assessment: adds decisions ADR-001…016, security model, aging/identity rules, privilege model, agent protocol and task catalog. |
| 1.1.0 | 2026-10-26 | Owner answers: name confirmed (ADR-001), GPL-3.0 (ADR-014), GitHub Actions (ADR-016), repository URL. The Owner's real network cannot provide ground truth, so G-1 and AC-13 are re-scoped to synthetic netns validation with impairment profiles P0–P3, scenarios S8/S9 added, risk R-15 added, T-105/T-106 updated, open items O-7/O-8 added. |

---

# Appendices

## Appendix A — Task Card Template (issued by the Manager)

```markdown
# TASK T-xxx — <title>
**Phase:** n · **Size:** S/M/L · **Depends on:** T-… · **Plan version:** x.y.z
**Plan references:** §…, FR-…, SR-…, ADR-…

## 1. Objective
<one paragraph: what outcome and why>

## 2. Context
<relevant decisions, prior reports, constraints from earlier tasks>

## 3. In scope
- …

## 4. Out of scope (do NOT do)
- …

## 5. Requirements
<specific behavior, interfaces, file/module locations>

## 6. Deliverables
<code, tests, docs, ADR updates, report path>

## 7. Acceptance criteria (each independently verifiable)
- [ ] …

## 8. Constraints
<dependency approvals, unsafe, performance, security notes>

## 9. Verification commands
<exact commands the executor must run and paste results of>

## 10. Report
Submit `docs/reports/T-xxx/execution-01.md` using Appendix B.
```

## Appendix B — Execution Report Template

```markdown
# Execution Report — T-xxx (attempt NN)
**Agent:** … · **Date:** … · **Branch/commits:** … · **Plan version:** …

## 1. Summary (≤ 5 lines)

## 2. Acceptance criteria
| AC | Status (Met / Partial / Not met) | Evidence (test name, command, file) |
|---|---|---|

## 3. What changed
<modules/files added or modified, with one line each>

## 4. Verification results
<each gate command and its result: fmt, clippy, test, doc, audit, deny, task-specific commands>

## 5. Deviations from the task card
<each with justification; "none" if none>

## 6. Decisions and assumptions
<each decision made, alternatives considered>

## 7. Dependencies
<added/changed crates with §9.2 evaluation; "none" if none>

## 8. Plan Questions
<PQ blocks per §14.5; "none" if none>

## 9. Security and privacy notes
<untrusted inputs touched, validation applied, privileges, data handling>

## 10. Known issues and limitations
## 11. Suggested follow-ups
```

## Appendix C — Review Report Template

```markdown
# Review Report — T-xxx (review of attempt NN)
**Reviewer:** … · **Date:** … · **Commit reviewed:** … · **Plan version:** …

## Verdict: APPROVE | APPROVE WITH FOLLOW-UPS | CHANGES REQUIRED | BLOCKED

## 1. Independent verification
<commands re-run by the reviewer and their results>

## 2. Acceptance criteria re-check
| AC | Met? | Reviewer evidence |
|---|---|---|

## 3. Checklist (§14.8)
| # | Item | Pass / Fail / N/A | Notes |
|---|---|---|---|

## 4. Findings
| ID | Severity | Location | Description | Recommendation |
|---|---|---|---|---|

## 5. Scope check
<anything outside the card or touching §2.2 / §2.3>

## 6. Test quality assessment
## 7. Security assessment
## 8. Report accuracy
<does the Execution Report match the diff?>

## 9. Recommendation to the Manager
```

## Appendix D — PoC Measurement Protocol (T-105) and Manual Test Matrix (T-406)

**Available environments (Owner decision, plan v1.1.0):** the Owner's real Wi-Fi network isolates clients, so it serves only as scenario (c). Ground-truth recall is therefore measured on synthetic networks. Scenarios: (c) the Owner's isolated Wi-Fi — observation only (expected near-zero visibility; verifies clean completion, the neighbor-table path and the honest UX); (e) netns synthetic, 250 hosts; (f) netns with proxy ARP; (g) container bridge; and optionally (a) wired /24, (b) non-isolated Wi-Fi, (d) Wi-Fi with many sleeping phones — if access becomes available, with a ground-truth device list.

**Impairment profiles for synthetic runs:** P0 none · P1 5% frame loss · P2 20% loss plus 50–200 ms delay/jitter · P3 sleepy hosts (helper responder ignores the first N requests, answers a fraction, or answers late).

**Per run record:** date, network type, scope size, mode, transport, rate, passes, sender IP variant, number of known devices, devices discovered per cycle (1–3), false/extra entries, time to first device, sweep duration, packets sent, replies received/rejected by reason, CPU time, notes on devices that never answered.

**Experiments:** transport comparison; `/proc/net/arp` vs netlink (value of neighbor state); rate 50/100/200 pps; passes 1/2/3; sender IP interface vs `0.0.0.0`; unicast refresh of known devices; periodic 1-pass recall over 10 cycles; behavior with the interface down/up mid-scan; behavior without `CAP_NET_RAW`.

**Report table (per network):**
| Variant | Recall cycle 1 | Recall cycle 3 | Extras | Time to first | Sweep time | Packets | Notes |
|---|---|---|---|---|---|---|---|

**Manual acceptance matrix (T-406)** re-runs the shipped binary on every available environment ((c) at minimum, plus (a), (b), (d) if available) together with the netns suites, and checks each AC from §19 with screenshots or terminal recordings stored without real identifiers.

## Appendix E — Reference Data Formats

- `/proc/net/arp`: header line, then `IP address · HW type · Flags · HW address · Mask · Device`. Flags `0x2` = complete, `0x0` = incomplete, `0x4` = permanent. Ignore unknown columns; tolerate any whitespace; treat the file as untrusted.
- `/proc/net/route`: `Iface · Destination · Gateway · Flags · RefCnt · Use · Metric · Mask · MTU · Window · IRTT`; values are hex, **little-endian** for addresses; default route has Destination and Mask `00000000`; Flags `0x1` UP, `0x2` GATEWAY.
- ARP request frame: Ethernet (dst `ff:ff:ff:ff:ff:ff`, src our MAC, ethertype `0x0806`) + ARP (htype 1, ptype `0x0800`, hlen 6, plen 4, opcode 1, sender MAC/IP ours, target MAC zero, target IP the probed address) = 42 bytes.
- MAC bits: first octet bit 0 = multicast; bit 1 = locally administered.
- IEEE registries: MA-L (24-bit), MA-M (28-bit), MA-S (36-bit). Lookup tries the longest prefix first.
- Private/shared ranges for FR-SC-07: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`.

## Appendix F — `AGENTS.md` Content (created by T-000)

```markdown
# AGENTS.md — rules for agents working on osza-netmon
Authority: plan.md. Read your task card and the plan sections it cites before coding.
1. Do exactly what the task card says. Out-of-scope ideas go to "Suggested follow-ups".
2. Stop and write a Plan Question when the plan is ambiguous or conflicts with the card.
3. No new dependencies without Manager approval. No `unsafe`. No println!/eprintln! outside main.rs pre-init/post-restore.
   New .rs files start with `// SPDX-License-Identifier: GPL-3.0-only`; dependencies must be GPL-3.0-compatible (deny.toml).
4. External input is hostile: validate at the boundary, never panic, bound all sizes and waits.
5. Never weaken, skip or delete tests to get green.
6. Run before submitting: cargo fmt --check; cargo clippy --all-targets --all-features -- -D warnings;
   cargo test --all-features; cargo doc --no-deps; cargo audit; cargo deny check.
7. Probe networks only inside netns or Owner-designated lab networks. Use synthetic data in fixtures/reports.
8. UI wording follows the controlled vocabulary (plan.md §5.4). Unknown stays "Unknown".
9. Submit docs/reports/T-xxx/execution-NN.md using the template in plan.md Appendix B.
10. Reviewers verify independently and never edit code; they write findings only.
```

## Appendix G — ADR Template

```markdown
# ADR-nnn: <title>
- **Status:** Accepted | Provisional | Pending | Open | Superseded by ADR-xxx
- **Date:** YYYY-MM-DD · **Deciding task / owner:** …
## Context
## Options considered
## Decision
## Consequences (positive, negative, follow-ups)
## Evidence (links to PoC data, reports, benchmarks)
```
