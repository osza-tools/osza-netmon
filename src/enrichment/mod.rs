// SPDX-License-Identifier: GPL-3.0-only

//! Enrichment: device-attribute lookups (plan §6.5).
//!
//! The enrichment layer turns observed identifiers into the
//! informational columns of the device list — vendor names and
//! hostnames — and is strictly read-only with respect to the model: it
//! answers queries, it never mutates device records (FR-RG-07 keeps
//! enrichment results out of the discovery truth). Per plan §8.2 this
//! module may depend on [`crate::model`] only.
//!
//! Task T-202 delivers [`vendor`]: the embedded, IEEE-OUI-derived
//! vendor database with longest-prefix lookup (FR-EN-01/FR-EN-02,
//! FR-EN-04).
//!
//! Task T-203 delivers the hostname enrichment (FR-EN-03, ADR-003,
//! ADR-015): [`hostname`] — the resolver-selection policy (D-1) and
//! [`hostname::HostnameConfig`]; [`dns`] — the PTR query/response
//! codec and the production [`dns::UdpResolver`] behind the
//! [`dns::NameResolver`] trait (D-2); and [`worker`] — the dedicated
//! worker thread with bounded queues, per-IP deduplication,
//! retry/backoff and the D-3 outcome mapping. The application core
//! (T-205) wires worker events into the registry; nothing here imports
//! `registry`.

pub mod dns;
pub mod hostname;
pub mod vendor;
pub mod worker;
