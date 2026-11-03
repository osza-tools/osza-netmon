# SOURCE.md — provenance of the embedded vendor database (`vendor-db.bin`)

Task T-202 (plan §6.5 FR-EN-02, §8.1 `data/oui/`). This file records where
the committed database comes from, how it is regenerated, and what was
found about the redistribution terms of the source data. Update this file
on every database refresh.

## Purpose

`data/oui/vendor-db.bin` is the compact, offline vendor-name database
embedded by `src/enrichment/vendor.rs` (`include_bytes!`) and served by
`VendorDb::lookup` (FR-EN-01: longest-prefix match 36 → 28 → 24 bits;
locally-administered MACs answered before any table access). It is built
from the four public IEEE registry CSVs by `examples/gen_oui.rs`. The
format (magic `OZOUDB`, version 1) is documented in the `vendor` module
docs; the loader is a total parser.

## Source files (retrieved 2026-11-03, UTC)

| Registry | URL | Retrieval date (UTC) | SHA-256 | Entries |
| --- | --- | --- | --- | --- |
| MA-L (24-bit) | https://standards-oui.ieee.org/oui/oui.csv | 2026-11-03 | `e8b6a42ff78ce6d28173513dbefb2620c50ff73780ae74b25472f89e6ec66b7a` | 40,442 |
| MA-M (28-bit) | https://standards-oui.ieee.org/oui28/mam.csv | 2026-11-03 | `543c6ba58adfd1cf25e02464336179036a6f7e2709ed2fd16e584ae8d2e33331` | 6,668 |
| MA-S (36-bit) | https://standards-oui.ieee.org/oui36/oui36.csv | 2026-11-03 | `6afd58412964f615d8926e5be1200d651885da75fa066b5339f5441f488abcd7` | 7,261 |
| IAB (36-bit legacy) | https://standards-oui.ieee.org/iab/iab.csv | 2026-11-03 | `6e71aa3d47f00f19d09cb3b31ce1038de1834703420f0ce4ce111da586f1a533` | 4,575 |

Total source rows: 58,946 (0 empty names, 239 names are the literal
string `Private`, 456 names contain non-ASCII characters, 73 exceed 64
characters, HTML entities appear as 13× `&amp;` and 6× `&quot;`). The raw
CSVs are **not** committed to this repository.

Note: the MA-M file was renamed by the IEEE from `oui28.csv` (now 404) to
`mam.csv`.

## Database file

* File: `data/oui/vendor-db.bin`
* SHA-256: `b0e21c99036eda8db09daccfd1030eea52c858c4a7b3b01f939d468379b585f4`
* Size: 1,514,769 bytes
* Embedded `DatabaseDate`: **2026-11-03** (the `--date` passed to
  `gen_oui`; the retrieval date of the CSVs above)
* Stored entries: 58,943 (MA-L 40,439 · MA-M 6,668 · MA-S 7,261 · IAB
  4,575) — 58,946 source rows minus 3 rows dropped as duplicates (below);
  usable entries after load-time sanitization: 58,943, skipped at load: 0.

## Dropped duplicate prefixes (policy D-3: same prefix AND same length —
the last row in file/merge order wins)

* `080030` (MA-L): kept **CERN**; dropped `NETWORK RESEARCH CORPORATION`,
  `ROYAL MELBOURNE INST OF TECH` (this file order).
* `0001C8` (MA-L): kept **CONRAD CORP.**; dropped `THOMAS CONRAD CORP.`
  (this file order).

## Data policies applied (T-202 task card §5, D-1…D-6)

* **D-1 Inputs:** the four CSVs above, read with the `csv` crate by header
  name (`Registry`, `Assignment`, `Organization Name`); UTF-8 BOM
  tolerated; malformed rows skipped and counted, never fatal (0 today).
* **D-2 Merge order:** MA-L, then MA-M, then MA-S, then IAB.
* **D-3 Duplicates:** same prefix and length → the last row in merge order
  wins (list above); different lengths never collide as keys.
* **D-4 Name normalization:** single left-to-right pass replacing exactly
  `&amp;` `&lt;` `&gt;` `&quot;` `&apos;`; no double unescaping
  (`&amp;gt;` stays `&gt;`); everything else verbatim.
* **D-5 "Private" names:** kept verbatim (239); empty/whitespace-only
  names skipped and counted (0 today).
* **D-6 Load-time sanitization:** every name passes `DisplayText::try_from`
  at load (whitespace runs collapse, control/bidi/zero-width characters
  removed, truncation to 64 characters); names that sanitize to empty are
  skipped and counted (0 for this build).

Determinism (D-8): identical inputs and date produce a byte-identical
image — two independent runs of the regeneration command below produced
the SHA-256 above both times.

## Redistribution terms found (D-9; checked 2026-11-03)

Pages checked and what they say:

1. https://standards.ieee.org/products-programs/regauth/ — the registry
   download page. Verbatim quotes:
   * "IEEE offers Registration Authority programs or registries which
     maintain lists of unique identifiers under standards and issue unique
     identifiers to those wishing to register them. The IEEE Registration
     Authority assigns unambiguous names to objects in a way which makes
     the assignment available to interested parties."
   * "Note: the CSV files below use the UTF-8 character set. Please open
     the files in an application that supports UTF-8."
   * Footer: "© Copyright 2026 IEEE – All rights reserved. A public
     charity, IEEE is the world's largest technical professional
     organization dedicated to advancing technology for the benefit of
     humanity."
   * No redistribution, reuse or licensing terms for the CSV files appear
     on this page.
2. https://standards.ieee.org/products-programs/regauth/faq/ — the
   linked FAQ ("The commonly most asked questions about our registries
   and how they are used"). No statement about redistribution, reuse or
   licensing of the registry files.
3. https://standards.ieee.org/about-us/policies/disclaimers/ — "Document
   Notices & Disclaimers Concerning IEEE Standards Documents": copyright,
   warranty and licensing terms for IEEE **standards documents**
   (including photocopy licensing via the Copyright Clearance Center and
   an AI-training restriction). Nothing in it addresses the registry CSV
   data files.

Finding: **no explicit permission — and no explicit prohibition — to
redistribute the registry data or a derived form of it was found.**

Assessment for this repository: the committed `vendor-db.bin` is a
mechanically derived, compact re-encoding (prefix tables plus verbatim
organization names) of publicly downloadable registry listings, embedded
in a GPL-3.0-only tool with this attribution record. Comparable derived
OUI lists have long been redistributed by open-source projects, and the
CSVs themselves are published without a click-through license. That is an
assessment, not legal advice; the absence of an explicit permission is
itself the finding, so this is raised as a Plan Question
(docs/reports/T-202/execution-01.md §8, PQ-1) for the Owner to resolve —
non-blocking for T-202, to be resolved before the 0.1.0 release.

## Regeneration

```sh
# From the repository root, with the four CSVs downloaded:
cargo run --locked --example gen_oui -- \
    --mal <oui.csv> --mam <mam.csv> --mas <oui36.csv> --iab <iab.csv> \
    --date 2026-11-03 --out data/oui/vendor-db.bin

# Record the hashes (the tool intentionally has no hashing dependency):
sha256sum data/oui/vendor-db.bin \
    <oui.csv> <mam.csv> <oui36.csv> <iab.csv>
```

The exact invocation used for the committed file (CSVs kept outside the
repository):

```sh
cargo run --locked --example gen_oui -- \
    --mal /home/z/my-project/ieee-raw/oui.csv \
    --mam /home/z/my-project/ieee-raw/mam.csv \
    --mas /home/z/my-project/ieee-raw/oui36.csv \
    --iab /home/z/my-project/ieee-raw/iab.csv \
    --date 2026-11-03 --out data/oui/vendor-db.bin
```

Determinism evidence: a second, independent run writing to a different
path produced the identical SHA-256
`b0e21c99036eda8db09daccfd1030eea52c858c4a7b3b01f939d468379b585f4`.

If a refresh changes any of the numbers above (entry counts, dropped
duplicates, hashes), update this file and the real-data expectations in
`src/enrichment/vendor.rs` (see the NOTE at the real-data test block) as
part of that refresh.

## License

This project is GPL-3.0-only (ADR-014; see `LICENSE`). The registry data
from which `vendor-db.bin` was derived is © IEEE (footer quote above);
the IEEE pages checked publish no explicit redistribution terms for it
(see the D-9 finding). The derived compact database is committed as part
of this GPL-3.0-only project with attribution and provenance recorded in
this file; the open redistribution question is tracked as PQ-1 of the
T-202 execution report and must be resolved before the 0.1.0 release.
