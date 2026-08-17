use std::fs;
use std::path::Path;

use rasp_core::{ExitCode, RaspError};
use serde::{Deserialize, Serialize};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("configuration validation failed: {0}")]
    Validation(String),
}

impl ConfigError {
    pub fn into_rasp_error(self) -> RaspError {
        RaspError::new(ExitCode::InvalidConfiguration, self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RaspConfig {
    pub schema_version: u32,
    pub application: ApplicationConfig,
    #[serde(default)]
    pub protections: ProtectionsConfig,
    pub risk_policy: RiskPolicyConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub android: AndroidConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationConfig {
    pub profile: String,
    pub expected_package_name: String,
    pub build_environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProtectionsConfig {
    #[serde(default)]
    pub application_signature: ProtectionRule,
    #[serde(default)]
    pub payload_integrity: ProtectionRule,
    #[serde(default)]
    pub javascript_bundle_integrity: JavascriptBundleIntegrity,
    #[serde(default)]
    pub flutter_integrity: FlutterIntegrity,
    #[serde(default)]
    pub debugger_detection: ProtectionRule,
    #[serde(default)]
    pub instrumentation_detection: ProtectionRule,
    #[serde(default)]
    pub memory_integrity: ProtectionRule,
    #[serde(default)]
    pub root_detection: ProtectionRule,
    #[serde(default)]
    pub emulator_detection: ProtectionRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProtectionRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub weight: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct JavascriptBundleIntegrity {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub weight: u8,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct FlutterIntegrity {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub weight: u8,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RiskPolicyConfig {
    pub thresholds: RiskThresholds,
    pub startup_signature_mismatch: RiskAction,
    pub startup_payload_tampering: RiskAction,
    pub runtime_high_risk: RiskAction,
    pub offline_behavior: OfflineBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RiskThresholds {
    pub report: u8,
    pub warn: u8,
    pub restrict: u8,
    pub terminate: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskAction {
    Allow,
    Report,
    Warn,
    LockStartup,
    Terminate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OfflineBehavior {
    ContinueWithLocalPolicy,
    FailClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub startup_budget_ms: u32,
    pub monitoring_enabled: bool,
    pub scan_interval_ms: ScanInterval,
    pub deep_scan_on_suspicion: bool,
    pub monitor_background_state: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            startup_budget_ms: 50,
            monitoring_enabled: true,
            scan_interval_ms: ScanInterval::default(),
            deep_scan_on_suspicion: true,
            monitor_background_state: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanInterval {
    pub minimum: u32,
    pub maximum: u32,
}

impl Default for ScanInterval {
    fn default() -> Self {
        Self {
            minimum: 5_000,
            maximum: 15_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AndroidConfig {
    pub initializer: AndroidInitializer,
    #[serde(default)]
    pub supported_abis: Vec<String>,
    #[serde(default)]
    pub initialize_processes: Vec<String>,
    pub minimum_sdk: u32,
    #[serde(default)]
    pub certificate_sha256: Vec<String>,
    #[serde(default)]
    pub preserve_signature_lineage: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidInitializer {
    ContentProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u32,
    #[serde(default)]
    pub include_device_identifiers: bool,
    #[serde(default)]
    pub include_raw_memory: bool,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: u32,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            connect_timeout_ms: default_connect_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            include_device_identifiers: false,
            include_raw_memory: false,
            queue_capacity: default_queue_capacity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    #[serde(default = "default_true")]
    pub generate_report: bool,
    #[serde(default = "default_true")]
    pub generate_sbom: bool,
    #[serde(default)]
    pub preserve_timestamps: bool,
    #[serde(default)]
    pub fail_on_warning: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            generate_report: true,
            generate_sbom: true,
            preserve_timestamps: false,
            fail_on_warning: false,
        }
    }
}

pub fn load_config(path: impl AsRef<Path>) -> Result<RaspConfig, ConfigError> {
    let contents = fs::read_to_string(path)?;
    parse_config(&contents)
}

pub fn parse_config(contents: &str) -> Result<RaspConfig, ConfigError> {
    let config: RaspConfig = serde_json::from_str(contents)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn validate_config(config: &RaspConfig) -> Result<(), ConfigError> {
    let mut errors = Vec::new();

    if config.schema_version != CONFIG_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {CONFIG_SCHEMA_VERSION}, got {}",
            config.schema_version
        ));
    }

    if !is_valid_android_package_name(&config.application.expected_package_name) {
        errors.push(format!(
            "application.expected_package_name is not a valid Android package name: {}",
            config.application.expected_package_name
        ));
    }

    validate_protection_weight(
        "protections.application_signature.weight",
        config.protections.application_signature.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.payload_integrity.weight",
        config.protections.payload_integrity.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.javascript_bundle_integrity.weight",
        config.protections.javascript_bundle_integrity.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.flutter_integrity.weight",
        config.protections.flutter_integrity.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.debugger_detection.weight",
        config.protections.debugger_detection.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.instrumentation_detection.weight",
        config.protections.instrumentation_detection.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.memory_integrity.weight",
        config.protections.memory_integrity.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.root_detection.weight",
        config.protections.root_detection.weight,
        &mut errors,
    );
    validate_protection_weight(
        "protections.emulator_detection.weight",
        config.protections.emulator_detection.weight,
        &mut errors,
    );

    let thresholds = &config.risk_policy.thresholds;
    if thresholds.report > 100
        || thresholds.warn > 100
        || thresholds.restrict > 100
        || thresholds.terminate > 100
    {
        errors.push("risk_policy.thresholds values must be from 0 to 100".to_string());
    }
    if !(thresholds.report < thresholds.warn
        && thresholds.warn < thresholds.restrict
        && thresholds.restrict < thresholds.terminate)
    {
        errors.push(
            "risk_policy.thresholds must be strictly increasing: report < warn < restrict < terminate"
                .to_string(),
        );
    }

    if config.runtime.scan_interval_ms.minimum == 0 {
        errors.push("runtime.scan_interval_ms.minimum must be greater than 0".to_string());
    }
    if config.runtime.scan_interval_ms.minimum > config.runtime.scan_interval_ms.maximum {
        errors.push(
            "runtime.scan_interval_ms.minimum must be less than or equal to maximum".to_string(),
        );
    }

    if config.android.minimum_sdk < 23 {
        errors.push("android.minimum_sdk must be at least 23 for Release 1.0".to_string());
    }

    if config.android.certificate_sha256.is_empty() {
        errors.push(
            "android.certificate_sha256 must contain at least one expected certificate".to_string(),
        );
    }
    for digest in &config.android.certificate_sha256 {
        if !is_valid_certificate_digest(digest) {
            errors.push(format!(
                "android.certificate_sha256 contains an invalid SHA-256 certificate digest: {digest}"
            ));
        }
    }

    for abi in &config.android.supported_abis {
        if !matches!(abi.as_str(), "arm64-v8a" | "armeabi-v7a" | "x86_64") {
            errors.push(format!(
                "android.supported_abis contains unsupported ABI: {abi}"
            ));
        }
    }

    if config.android.initialize_processes.is_empty() {
        errors.push("android.initialize_processes must contain \"main\"".to_string());
    }
    for process in &config.android.initialize_processes {
        if process != "main" {
            errors.push(format!(
                "android.initialize_processes supports only \"main\" for Release 1.0: {process}"
            ));
        }
    }

    if config.telemetry.enabled {
        let endpoint = config.telemetry.endpoint.as_deref().unwrap_or_default();
        if endpoint.trim().is_empty() {
            errors
                .push("telemetry.endpoint is required when telemetry.enabled is true".to_string());
        }
    }

    if config.telemetry.include_raw_memory {
        errors.push("telemetry.include_raw_memory must remain false".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Validation(errors.join("; ")))
    }
}

pub fn is_valid_android_package_name(value: &str) -> bool {
    let mut segment_count = 0usize;
    for segment in value.split('.') {
        segment_count += 1;
        if segment.is_empty() {
            return false;
        }

        let mut chars = segment.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }

        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }

    segment_count >= 2
}

pub fn is_valid_env_var_name(value: &str) -> bool {
    if value.contains('=') || value.trim() != value {
        return false;
    }

    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_protection_weight(name: &str, weight: u8, errors: &mut Vec<String>) {
    if weight > 100 {
        errors.push(format!("{name} must be from 0 to 100"));
    }
}

fn is_valid_certificate_digest(value: &str) -> bool {
    value == "CURRENT_SIGNING_CERTIFICATE_SHA256"
        || (value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout_ms() -> u32 {
    3_000
}

fn default_request_timeout_ms() -> u32 {
    5_000
}

fn default_queue_capacity() -> u32 {
    100
}

#[cfg(test)]
mod tests {
    use super::{is_valid_env_var_name, parse_config};

    const VALID_CONFIG: &str = r#"{
      "schema_version": 1,
      "application": {
        "profile": "banking-strict",
        "expected_package_name": "com.example.mobile",
        "build_environment": "production"
      },
      "protections": {
        "application_signature": { "enabled": true, "weight": 100 },
        "payload_integrity": { "enabled": true, "weight": 100 },
        "javascript_bundle_integrity": {
          "enabled": true,
          "weight": 80,
          "paths": ["assets/index.android.bundle"]
        },
        "flutter_integrity": {
          "enabled": false,
          "weight": 80,
          "paths": []
        },
        "debugger_detection": { "enabled": true, "weight": 40 },
        "instrumentation_detection": { "enabled": true, "weight": 60 },
        "memory_integrity": { "enabled": true, "weight": 60 },
        "root_detection": { "enabled": true, "weight": 20 },
        "emulator_detection": { "enabled": false, "weight": 10 }
      },
      "risk_policy": {
        "thresholds": { "report": 20, "warn": 40, "restrict": 70, "terminate": 100 },
        "startup_signature_mismatch": "TERMINATE",
        "startup_payload_tampering": "TERMINATE",
        "runtime_high_risk": "REPORT",
        "offline_behavior": "CONTINUE_WITH_LOCAL_POLICY"
      },
      "runtime": {
        "startup_budget_ms": 50,
        "monitoring_enabled": true,
        "scan_interval_ms": { "minimum": 5000, "maximum": 15000 },
        "deep_scan_on_suspicion": true,
        "monitor_background_state": false
      },
      "android": {
        "initializer": "CONTENT_PROVIDER",
        "supported_abis": ["arm64-v8a", "armeabi-v7a"],
        "initialize_processes": ["main"],
        "minimum_sdk": 23,
        "certificate_sha256": ["CURRENT_SIGNING_CERTIFICATE_SHA256"],
        "preserve_signature_lineage": false
      },
      "telemetry": {
        "enabled": false,
        "endpoint": null,
        "connect_timeout_ms": 3000,
        "request_timeout_ms": 5000,
        "include_device_identifiers": false,
        "include_raw_memory": false,
        "queue_capacity": 100
      },
      "output": {
        "generate_report": true,
        "generate_sbom": true,
        "preserve_timestamps": false,
        "fail_on_warning": false
      }
    }"#;

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("valid config");
        assert_eq!(
            config.application.expected_package_name,
            "com.example.mobile"
        );
    }

    #[test]
    fn rejects_unknown_top_level_property() {
        let invalid = VALID_CONFIG.replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"extra\": true,",
        );
        let error = parse_config(&invalid).expect_err("unknown property should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_non_monotonic_thresholds() {
        let invalid = VALID_CONFIG.replace(
            "\"thresholds\": { \"report\": 20, \"warn\": 40, \"restrict\": 70, \"terminate\": 100 }",
            "\"thresholds\": { \"report\": 20, \"warn\": 10, \"restrict\": 70, \"terminate\": 100 }",
        );
        let error = parse_config(&invalid).expect_err("non-monotonic thresholds should fail");
        assert!(error.to_string().contains("strictly increasing"));
    }

    #[test]
    fn rejects_raw_memory_collection() {
        let invalid = VALID_CONFIG.replace(
            "\"include_raw_memory\": false",
            "\"include_raw_memory\": true",
        );
        let error = parse_config(&invalid).expect_err("raw memory should fail");
        assert!(error.to_string().contains("include_raw_memory"));
    }

    #[test]
    fn rejects_empty_initialize_processes() {
        let invalid = VALID_CONFIG.replace(
            "\"initialize_processes\": [\"main\"]",
            "\"initialize_processes\": []",
        );
        let error = parse_config(&invalid).expect_err("empty process list should fail");
        assert!(error.to_string().contains("initialize_processes"));
    }

    #[test]
    fn rejects_unsupported_initialize_processes() {
        let invalid = VALID_CONFIG.replace(
            "\"initialize_processes\": [\"main\"]",
            "\"initialize_processes\": [\"main\", \"remote\"]",
        );
        let error = parse_config(&invalid).expect_err("remote process should fail");
        assert!(error.to_string().contains("supports only \"main\""));
    }

    #[test]
    fn validates_environment_variable_names() {
        assert!(is_valid_env_var_name("KEYSTORE_PASSWORD"));
        assert!(is_valid_env_var_name("_KEY_PASSWORD_2"));
        assert!(!is_valid_env_var_name("KEYSTORE_PASSWORD=secret"));
        assert!(!is_valid_env_var_name("1PASSWORD"));
        assert!(!is_valid_env_var_name(" PASSWORD"));
    }
}
