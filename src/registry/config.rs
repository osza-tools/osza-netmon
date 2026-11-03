// SPDX-License-Identifier: GPL-3.0-only

//! Registry tuning parameters: [`RegistryConfig`] with the ADR-007 /
//! ADR-008 defaults, and the [`ConfigError`] rejections
//! (task T-201).
//!
//! Every parameter of the two ADRs is configurable so the rules can be
//! exercised at their boundaries in tests, but the defaults are exactly
//! the ADR values: 3 missed cycles, 120 s age floor, 5-IP shared-MAC
//! threshold, 4,096-key hard cap.

use std::time::Duration;

/// Default `idle_after_cycles` (ADR-007): a device may become Idle after
/// being absent from 3 consecutive complete scan cycles.
pub const IDLE_AFTER_CYCLES_DEFAULT: u32 = 3;

/// Default `idle_min_age` (ADR-007): the age floor; a device may become
/// Idle only once `now − last_seen ≥ 120 s`. It prevents manual-refresh
/// spamming from idling everything within seconds.
pub const IDLE_MIN_AGE_DEFAULT: Duration = Duration::from_secs(120);

/// Default `shared_mac_threshold` (ADR-008): one MAC observed with at
/// least 5 distinct IPs within the idle window gets the `Multiple IPs`
/// tag with a neutral explanation.
pub const SHARED_MAC_THRESHOLD_DEFAULT: u32 = 5;

/// The registry hard cap (ADR-008): at most 4,096 device keys. Beyond
/// it, new keys are dropped, existing ones still update, and a
/// persistent warning is exposed.
pub const REGISTRY_CAP: usize = 4096;

/// Tuning parameters of the registry, with the ADR-007/ADR-008 defaults.
///
/// All fields are public and the type is `Copy`, but a config is only
/// accepted by [`Registry::new`](super::Registry::new) after
/// validation — an inconsistent combination (for example a zero cycle
/// count) is a rejected [`ConfigError`] instead of a silently clamped
/// value (plan §8.7: nothing is repaired silently).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryConfig {
    /// Consecutive complete cycles a device must be absent from before
    /// it may become Idle (ADR-007). Must be ≥ 1.
    pub idle_after_cycles: u32,
    /// The age floor: a device may become Idle only once
    /// `now − last_seen ≥ idle_min_age` (ADR-007). Must be non-zero.
    pub idle_min_age: Duration,
    /// Distinct IPs within the idle window that trigger the
    /// `Multiple IPs` tag on one MAC (ADR-008). Must be ≥ 2 — a
    /// threshold of 1 would label every device that has ever been
    /// observed.
    pub shared_mac_threshold: u32,
    /// The maximum number of device keys; 1..=[`REGISTRY_CAP`]. The ADR
    /// hard cap is the ceiling, smaller values are allowed so cap
    /// behavior can be tested cheaply.
    pub max_devices: usize,
}

impl Default for RegistryConfig {
    /// The ADR-007/ADR-008 values: 3 cycles, 120 s, 5 IPs, 4,096 keys.
    fn default() -> Self {
        RegistryConfig {
            idle_after_cycles: IDLE_AFTER_CYCLES_DEFAULT,
            idle_min_age: IDLE_MIN_AGE_DEFAULT,
            shared_mac_threshold: SHARED_MAC_THRESHOLD_DEFAULT,
            max_devices: REGISTRY_CAP,
        }
    }
}

impl RegistryConfig {
    /// Builds and validates a config from its four parameters.
    pub fn try_new(
        idle_after_cycles: u32,
        idle_min_age: Duration,
        shared_mac_threshold: u32,
        max_devices: usize,
    ) -> Result<Self, ConfigError> {
        let config = RegistryConfig {
            idle_after_cycles,
            idle_min_age,
            shared_mac_threshold,
            max_devices,
        };
        config.validate()?;
        Ok(config)
    }

    /// Rejects inconsistent combinations, returning the first violation.
    ///
    /// Public so callers can pre-validate; [`Registry::new`](super::Registry::new)
    /// runs the same check.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.idle_after_cycles == 0 {
            return Err(ConfigError::IdleAfterCyclesZero);
        }
        if self.idle_min_age.is_zero() {
            return Err(ConfigError::IdleMinAgeZero);
        }
        if self.shared_mac_threshold < 2 {
            return Err(ConfigError::SharedMacThresholdTooLow {
                found: self.shared_mac_threshold,
            });
        }
        if self.max_devices == 0 || self.max_devices > REGISTRY_CAP {
            return Err(ConfigError::MaxDevicesOutOfRange {
                found: self.max_devices,
            });
        }
        Ok(())
    }
}

/// Why a [`RegistryConfig`] was rejected.
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `idle_after_cycles` was zero; aging would fire on the age floor
    /// alone, which ADR-007 forbids.
    #[error("idle_after_cycles must be at least 1")]
    IdleAfterCyclesZero,
    /// `idle_min_age` was zero; the age floor would not exist.
    #[error("idle_min_age must be greater than zero")]
    IdleMinAgeZero,
    /// `shared_mac_threshold` was below 2; every observed device would
    /// be tagged `Multiple IPs`.
    #[error("shared_mac_threshold must be at least 2, found {found}")]
    SharedMacThresholdTooLow {
        /// The rejected value.
        found: u32,
    },
    /// `max_devices` was zero or above the ADR-008 hard cap.
    #[error("max_devices must be between 1 and the hard cap {REGISTRY_CAP}, found {found}")]
    MaxDevicesOutOfRange {
        /// The rejected value.
        found: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_exactly_the_adr_values() {
        let config = RegistryConfig::default();
        assert_eq!(config.idle_after_cycles, 3, "ADR-007 default");
        assert_eq!(
            config.idle_min_age,
            Duration::from_secs(120),
            "ADR-007 default"
        );
        assert_eq!(config.shared_mac_threshold, 5, "ADR-008 default");
        assert_eq!(config.max_devices, 4096, "ADR-008 hard cap");
        assert_eq!(IDLE_AFTER_CYCLES_DEFAULT, 3);
        assert_eq!(IDLE_MIN_AGE_DEFAULT, Duration::from_secs(120));
        assert_eq!(SHARED_MAC_THRESHOLD_DEFAULT, 5);
        assert_eq!(REGISTRY_CAP, 4096);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn try_new_validates_every_parameter() {
        assert!(RegistryConfig::try_new(3, Duration::from_secs(120), 5, 4096).is_ok());
        assert_eq!(
            RegistryConfig::try_new(0, Duration::from_secs(120), 5, 4096).unwrap_err(),
            ConfigError::IdleAfterCyclesZero
        );
        assert_eq!(
            RegistryConfig::try_new(3, Duration::ZERO, 5, 4096).unwrap_err(),
            ConfigError::IdleMinAgeZero
        );
        assert_eq!(
            RegistryConfig::try_new(3, Duration::from_secs(120), 1, 4096).unwrap_err(),
            ConfigError::SharedMacThresholdTooLow { found: 1 }
        );
        assert_eq!(
            RegistryConfig::try_new(3, Duration::from_secs(120), 5, 0).unwrap_err(),
            ConfigError::MaxDevicesOutOfRange { found: 0 }
        );
        assert_eq!(
            RegistryConfig::try_new(3, Duration::from_secs(120), 5, 4097).unwrap_err(),
            ConfigError::MaxDevicesOutOfRange { found: 4097 }
        );
    }

    #[test]
    fn field_built_configs_are_rejected_at_the_same_boundary() {
        // The struct has public fields, so validation must also catch a
        // hand-assembled config — Registry::new re-runs validate().
        let zero_cycles = RegistryConfig {
            idle_after_cycles: 0,
            ..RegistryConfig::default()
        };
        assert_eq!(
            zero_cycles.validate().unwrap_err(),
            ConfigError::IdleAfterCyclesZero
        );
        let zero_threshold = RegistryConfig {
            shared_mac_threshold: 0,
            ..RegistryConfig::default()
        };
        assert!(zero_threshold.validate().is_err());
        // A smaller-than-cap device limit is legal (for cap tests).
        let small = RegistryConfig::try_new(1, Duration::from_secs(1), 2, 3);
        assert_eq!(small.unwrap().max_devices, 3);
    }

    #[test]
    fn error_messages_are_one_line_and_factual() {
        assert_eq!(
            ConfigError::IdleAfterCyclesZero.to_string(),
            "idle_after_cycles must be at least 1"
        );
        assert_eq!(
            ConfigError::SharedMacThresholdTooLow { found: 1 }.to_string(),
            "shared_mac_threshold must be at least 2, found 1"
        );
        assert_eq!(
            ConfigError::MaxDevicesOutOfRange { found: 5000 }.to_string(),
            "max_devices must be between 1 and the hard cap 4096, found 5000"
        );
    }
}
