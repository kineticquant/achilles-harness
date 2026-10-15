//! Central Jev configuration contract: key names, defaults, and the toggle
//! checks every feature must go through.
//!
//! Toggle model: `JEV_ENABLED` is the master switch and each feature has its
//! own flag (`JEV_ROUTER_ENABLED`, `JEV_GUARD_ENABLED`, `JEV_TRIAGE_ENABLED`).
//! Everything defaults off; unset or invalid values count as off. No API key
//! means no calls regardless of toggles.

use crate::config::Config;

/// Master switch: no Jev feature may act unless this is on.
pub const MASTER_FLAG: &str = "JEV_ENABLED";
/// Per-feature switches.
pub const ROUTER_FLAG: &str = "JEV_ROUTER_ENABLED";
pub const GUARD_FLAG: &str = "JEV_GUARD_ENABLED";
pub const TRIAGE_FLAG: &str = "JEV_TRIAGE_ENABLED";
/// Client credentials and transport.
pub const API_KEY: &str = "JEV_API_KEY";
pub const ENDPOINT_KEY: &str = "JEV_ENDPOINT";
pub const MODEL_KEY: &str = "JEV_MODEL";
pub const TIMEOUT_MS_KEY: &str = "JEV_TIMEOUT_MS";
/// Router policy (JSON) and confidence gate.
pub const ROUTER_POLICY_KEY: &str = "JEV_ROUTER_POLICY";
pub const ROUTER_CONFIDENCE_KEY: &str = "JEV_ROUTER_CONFIDENCE_THRESHOLD";
/// Guard block threshold.
pub const GUARD_THRESHOLD_KEY: &str = "JEV_GUARD_THRESHOLD";
/// Triage auto-apply gate and scan auto-pass.
pub const TRIAGE_CONFIDENCE_KEY: &str = "JEV_TRIAGE_CONFIDENCE_THRESHOLD";
pub const TRIAGE_AUTO_KEY: &str = "JEV_TRIAGE_AUTO";

/// Master switch plus per-feature flag. Unset or invalid values count as off.
pub fn feature_enabled(feature_flag: &str) -> bool {
    let config = Config::global();
    config.get_param::<bool>(MASTER_FLAG).unwrap_or(false)
        && config.get_param::<bool>(feature_flag).unwrap_or(false)
}

/// Guard decision bands: `risk >= block_at` forces an approval prompt;
/// `ask_at <= risk < block_at` is recorded but allows the call;
/// below `ask_at` is clean.
pub struct GuardThresholds {
    pub block_at: f64,
    pub ask_at: f64,
}

impl Default for GuardThresholds {
    fn default() -> Self {
        Self {
            block_at: 0.8,
            ask_at: 0.5,
        }
    }
}

/// Triage auto-apply gate: decisions need `confidence >= auto_at`.
pub struct TriageThresholds {
    pub auto_at: f64,
}

impl Default for TriageThresholds {
    fn default() -> Self {
        Self { auto_at: 0.8 }
    }
}

/// Block threshold, overridable via `JEV_GUARD_THRESHOLD`.
pub fn guard_thresholds() -> GuardThresholds {
    let block_at = Config::global()
        .get_param::<f64>(GUARD_THRESHOLD_KEY)
        .unwrap_or(GuardThresholds::default().block_at);
    GuardThresholds {
        block_at,
        ..GuardThresholds::default()
    }
}

/// Auto-apply gate, overridable via `JEV_TRIAGE_CONFIDENCE_THRESHOLD`.
pub fn triage_thresholds() -> TriageThresholds {
    let auto_at = Config::global()
        .get_param::<f64>(TRIAGE_CONFIDENCE_KEY)
        .unwrap_or(TriageThresholds::default().auto_at);
    TriageThresholds { auto_at }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_all(
        master: Option<&str>,
        router: Option<&str>,
        guard: Option<&str>,
        triage: Option<&str>,
    ) -> env_lock::EnvGuard<'static> {
        env_lock::lock_env([
            ("JEV_ENABLED", master),
            ("JEV_ROUTER_ENABLED", router),
            ("JEV_GUARD_ENABLED", guard),
            ("JEV_TRIAGE_ENABLED", triage),
        ])
    }

    #[test]
    #[serial_test::serial]
    fn everything_off_by_default() {
        let _guard = lock_all(None, None, None, None);
        assert!(!feature_enabled(ROUTER_FLAG));
        assert!(!feature_enabled(GUARD_FLAG));
        assert!(!feature_enabled(TRIAGE_FLAG));
    }

    #[test]
    #[serial_test::serial]
    fn feature_needs_master_and_own_flag() {
        let _guard = lock_all(Some("true"), Some("true"), None, None);
        assert!(feature_enabled(ROUTER_FLAG));
        assert!(!feature_enabled(GUARD_FLAG));
    }

    #[test]
    #[serial_test::serial]
    fn master_off_disables_everything() {
        let _guard = lock_all(Some("false"), Some("true"), Some("true"), Some("true"));
        assert!(!feature_enabled(ROUTER_FLAG));
        assert!(!feature_enabled(GUARD_FLAG));
        assert!(!feature_enabled(TRIAGE_FLAG));
    }

    #[test]
    #[serial_test::serial]
    fn invalid_values_count_as_off() {
        let _guard = lock_all(Some("yes"), Some("1"), Some("on"), Some("true"));
        assert!(!feature_enabled(ROUTER_FLAG));
        assert!(!feature_enabled(GUARD_FLAG));
        assert!(!feature_enabled(TRIAGE_FLAG));
    }

    #[test]
    fn key_constants_match_plan() {
        assert_eq!(API_KEY, "JEV_API_KEY");
        assert_eq!(ENDPOINT_KEY, "JEV_ENDPOINT");
        assert_eq!(MODEL_KEY, "JEV_MODEL");
        assert_eq!(TIMEOUT_MS_KEY, "JEV_TIMEOUT_MS");
        assert_eq!(ROUTER_FLAG, "JEV_ROUTER_ENABLED");
        assert_eq!(GUARD_FLAG, "JEV_GUARD_ENABLED");
        assert_eq!(TRIAGE_FLAG, "JEV_TRIAGE_ENABLED");
    }

    #[test]
    #[serial_test::serial]
    fn thresholds_default_and_env_override() {
        {
            let _guard = env_lock::lock_env([
                ("JEV_GUARD_THRESHOLD", None::<&str>),
                ("JEV_TRIAGE_CONFIDENCE_THRESHOLD", None::<&str>),
            ]);
            assert!((guard_thresholds().block_at - 0.8).abs() < f64::EPSILON);
            assert!((guard_thresholds().ask_at - 0.5).abs() < f64::EPSILON);
            assert!((triage_thresholds().auto_at - 0.8).abs() < f64::EPSILON);
        }
        {
            let _guard = env_lock::lock_env([
                ("JEV_GUARD_THRESHOLD", Some("0.9")),
                ("JEV_TRIAGE_CONFIDENCE_THRESHOLD", Some("0.7")),
            ]);
            assert!((guard_thresholds().block_at - 0.9).abs() < f64::EPSILON);
            assert!((triage_thresholds().auto_at - 0.7).abs() < f64::EPSILON);
        }
    }
}
