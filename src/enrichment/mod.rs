// SPDX-License-Identifier: GPL-3.0-only

//! Enrichment: offline device-attribute lookups (plan §6.5).
//!
//! The enrichment layer turns observed identifiers into the informational
//! columns of the device list — vendor names and (with T-203) hostnames —
//! and is strictly read-only with respect to the model: it answers
//! queries, it never mutates device records (FR-RG-07 keeps enrichment
//! results out of the discovery truth). Per plan §8.2 this module may
//! depend on [`crate::model`] only.
//!
//! Task T-202 delivers [`vendor`]: the embedded, IEEE-OUI-derived vendor
//! database with longest-prefix lookup (FR-EN-01/FR-EN-02, FR-EN-04).
//! The hostname resolver (FR-EN-03, ADR-003/ADR-015) arrives with T-203.

pub mod vendor;
