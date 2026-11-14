// SPDX-License-Identifier: GPL-3.0-only

//! Session parameters and the construction error of the application
//! state (plan §8.1 `config` role for the app layer; task T-205).
//!
//! [`SessionParams`] is the bundle the startup assembly (T-301/T-302)
//! computes once before building [`AppState`](super::AppState):
//! the rediscovery interval, the hostname feature knobs, the
//! notice-acknowledgment state (the persistence file is T-302's), the
//! root check of §5.10, the session mode, the active-scan host cap
//! (T-302), and the two reviewed-layer configs (registry, hostname
//! worker). Everything has a documented default; the assembly
//! overrides per its CLI/environment findings.
//!
//! [`AppMode`] distinguishes the active session from the read-only one
//! (FR-DS-14): read-only mode is entered when the raw socket cannot be
//! opened (an `EPERM` at open time, ADR-005) — the reason text is
//! supplied by the caller and stored verbatim (T-401 words it).
//!
//! [`AppInitError`] is the one fallible part of
//! [`AppState::new`](super::AppState::new): the registry configuration
//! validation (plan §8.7: an out-of-range value is a typed error, not
//! a silently clamped one). The hostname config is taken as given —
//! its own validation lives behind `HostnameConfig::try_new`, which
//! the assembly (or the test) applies before handing the config over.

use std::net::SocketAddr;

use crate::discovery::scheduler::RediscoveryInterval;
use crate::enrichment::hostname::HostnameConfig;
use crate::model::ipv4::DEFAULT_MAX_HOSTS;
use crate::registry::RegistryConfig;

/// The authorization notice's text version (ADR-004; the O-6 ruling of
/// plan v1.12.0: the full notice shows on first run **or whenever the
/// notice text version changes**).
///
/// This constant is the version the application persists in the ack
/// record and re-checks on every start; it starts at 1 and bumps only
/// when the notice text (rendered by the ui layer's notice screen,
/// ADR-004 verbatim)
/// changes. Task T-302's E-2a effect
/// ([`PersistNoticeAck`](super::action::Effect::PersistNoticeAck))
/// carries it; the file format is governed by ADR-004/ADR-013.
pub const NOTICE_VERSION: u32 = 1;

/// Which machinery the session runs (FR-DS-14).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AppMode {
    /// Neighbor reads plus the paced ARP sweep (the reviewed T-104
    /// path, entered when the raw socket opens).
    #[default]
    Active,
    /// Neighbor reads only — no socket exists in this mode. The
    /// reason is the caller's explanation (why the socket could not
    /// be opened), stored verbatim; T-401 words the §6.8 message.
    ReadOnly {
        /// Why the session is read-only, verbatim from the caller.
        reason: String,
    },
}

/// Everything the startup assembly hands to
/// [`AppState::new`](super::AppState::new) (§5.4). Field defaults are
/// the plan values: 60 s rediscovery (FR-DS-12), hostnames enabled,
/// notice not yet acknowledged, not root, active mode, and the
/// reviewed layers' default configs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionParams {
    /// The periodic rediscovery interval (default 60 s;
    /// `Duration::ZERO` = manual-only, FR-DS-12 ruling (f)).
    pub interval: RediscoveryInterval,
    /// Whether hostname lookups are queued at all (the app-level knob
    /// behind `--no-hostnames`, T-402; default `true`). Kept consistent
    /// with [`Self::hostname`]'s own `enabled` flag by the assembly.
    pub hostnames_enabled: bool,
    /// Whether the §14 notice was already acknowledged in a previous
    /// session (the persistence file is T-302's; here: a startup
    /// parameter).
    pub notice_acknowledged: bool,
    /// Whether the process was started as root (ADR-005 item 5; filled
    /// from [`running_as_root`](crate::discovery::privilege::running_as_root)
    /// by the assembly — the one privilege helper §5.10 assigns to
    /// this card).
    pub started_as_root: bool,
    /// The active-scan host cap (FR-SC-06, task T-302's E-2d): the
    /// number of probe targets above which a confirmed network is
    /// either refused (at the default cap, read-only remaining) or —
    /// when the cap was raised — requires the in-app large-scope
    /// confirmation. Default
    /// [`DEFAULT_MAX_HOSTS`] (1,022 = /22); the assembly rejects
    /// values above
    /// [`ABSOLUTE_MAX_HOSTS`](crate::model::ipv4::ABSOLUTE_MAX_HOSTS)
    /// (65,534) before the state exists (T-402's parser re-checks).
    pub max_hosts: u32,
    /// The session's mode (FR-DS-14).
    pub mode: AppMode,
    /// The registry tuning (ADR-007/ADR-008 defaults by default).
    pub registry: RegistryConfig,
    /// The hostname worker tuning (ADR-003 defaults by default).
    pub hostname: HostnameConfig,
    /// The resolver the assembly selected (ADR-003), for the startup
    /// message only. `None` ⇒ the §6.8 "no eligible local resolver"
    /// message (lookups still flow — the `None`-resolver worker
    /// answers `Unavailable(NoResolver)` honestly, T-203).
    pub resolver_selected: Option<SocketAddr>,
}

impl Default for SessionParams {
    /// The plan defaults: 60 s interval, hostnames on, notice pending,
    /// non-root, active mode, the default 1,022-host cap, reviewed-
    /// layer defaults, no resolver selected yet.
    fn default() -> Self {
        SessionParams {
            interval: RediscoveryInterval::default(),
            hostnames_enabled: true,
            notice_acknowledged: false,
            started_as_root: false,
            max_hosts: DEFAULT_MAX_HOSTS,
            mode: AppMode::default(),
            registry: RegistryConfig::default(),
            hostname: HostnameConfig::default(),
            resolver_selected: None,
        }
    }
}

/// Why [`AppState::new`](super::AppState::new) refused to build the
/// application state. One cause exists: the registry configuration
/// failed validation (§5.4; nothing is clamped or repaired silently,
/// plan §8.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppInitError {
    /// The registry configuration is invalid (the registry's own typed
    /// error, verbatim).
    #[error("the registry configuration is invalid: {0}")]
    Registry(
        /// The registry's typed validation error.
        crate::registry::ConfigError,
    ),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn defaults_are_the_plan_values() {
        let params = SessionParams::default();
        assert_eq!(
            params.interval.interval(),
            Duration::from_secs(60),
            "FR-DS-12 default 60 s"
        );
        assert!(params.hostnames_enabled);
        assert!(!params.notice_acknowledged);
        assert!(!params.started_as_root);
        assert_eq!(params.max_hosts, DEFAULT_MAX_HOSTS, "FR-SC-06 default");
        assert_eq!(params.mode, AppMode::Active);
        assert_eq!(params.registry, RegistryConfig::default());
        assert_eq!(params.hostname, HostnameConfig::default());
        assert_eq!(params.resolver_selected, None);
    }

    #[test]
    fn the_notice_version_starts_at_one() {
        // ADR-004 / O-6 (v1.12.0): the version governs when the full
        // notice re-appears; it starts at 1 and bumps only when the
        // notice text changes. The pin here is the anchor of that
        // contract — a bump is a deliberate, reviewable change.
        assert_eq!(NOTICE_VERSION, 1);
    }

    #[test]
    fn an_invalid_registry_config_is_a_typed_init_error() {
        // max_devices = 0 is invalid (REGISTRY_CAP bounds); the state
        // constructor must refuse it (plan §8.7), not clamp it.
        let mut params = SessionParams::default();
        params.registry.max_devices = 0;
        let result = super::super::state::AppState::with_scope_entries(
            params,
            Vec::new(),
            std::sync::Arc::new(vendor_db_for_tests()),
            &crate::model::FakeClock::new(),
        );
        let error = match result {
            Ok(_) => panic!("an invalid config must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, AppInitError::Registry(_)), "{error}");
        // The error names the registry's own reason, verbatim.
        let rendered = error.to_string();
        assert!(
            rendered.contains("registry configuration is invalid"),
            "{rendered}"
        );
    }

    /// The embedded vendor database (committed image, T-202) — valid
    /// by construction, so every config test can build a state.
    fn vendor_db_for_tests() -> crate::enrichment::vendor::VendorDb {
        crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid")
    }
}
