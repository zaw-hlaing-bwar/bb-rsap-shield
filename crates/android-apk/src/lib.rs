use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use android_axml::{
    bootstrap_provider_authority, inject_manifest_provider, parse_manifest, ManifestProvider,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MAX_APK_ENTRIES: usize = 200_000;
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const ANDROID_MANIFEST_PATH: &str = "AndroidManifest.xml";
const SIGNATURE_MANIFEST_ENTRY: &str = "META-INF/MANIFEST.MF";
const BOOTSTRAP_DEX_FILE: &str = "bootstrap.dex";
const SECURITY_LIBRARY_NAME: &str = "libsecurity.so";
pub const INTEGRITY_MANIFEST_ENTRY: &str = "assets/rasp-shield/integrity-manifest.json";
pub const INTEGRITY_MANIFEST_SCHEMA_VERSION: u32 = 1;

pub fn default_runtime_policy() -> IntegrityRuntimePolicy {
    IntegrityRuntimePolicy {
        thresholds: IntegrityRiskThresholds {
            report: 20,
            warn: 40,
            restrict: 70,
            terminate: 100,
        },
        startup_budget_ms: default_startup_budget_ms(),
        runtime_high_risk_action: IntegrityRiskAction::Report,
        startup_integrity_action: IntegrityRiskAction::Terminate,
        startup_payload_tampering_action: IntegrityRiskAction::Terminate,
        monitoring: IntegrityRuntimeMonitoring {
            enabled: true,
            scan_interval_minimum_ms: 5_000,
            scan_interval_maximum_ms: 15_000,
            deep_scan_on_suspicion: true,
            monitor_background_state: false,
        },
        detections: default_runtime_detections(),
    }
}

pub fn default_startup_integrity_action() -> IntegrityRiskAction {
    IntegrityRiskAction::Terminate
}

pub fn default_startup_payload_tampering_action() -> IntegrityRiskAction {
    IntegrityRiskAction::Terminate
}

pub fn default_runtime_monitoring() -> IntegrityRuntimeMonitoring {
    default_runtime_policy().monitoring
}

pub fn default_runtime_detections() -> IntegrityRuntimeDetections {
    IntegrityRuntimeDetections {
        debugger: IntegrityDetectionRule {
            enabled: true,
            weight: 40,
        },
        instrumentation: IntegrityDetectionRule {
            enabled: true,
            weight: 60,
        },
        memory: IntegrityDetectionRule {
            enabled: true,
            weight: 60,
        },
        root: IntegrityDetectionRule {
            enabled: true,
            weight: 20,
        },
        emulator: IntegrityDetectionRule {
            enabled: false,
            weight: 10,
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApkEntry {
    pub path: String,
    pub compressed: bool,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFiles {
    pub bootstrap_dex_path: PathBuf,
    pub abi_libraries: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkRewriteOptions {
    pub build_id: String,
    pub provider_init_order: i32,
    pub integrity_manifest: IntegrityManifestInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityManifestInput {
    pub application_profile: String,
    pub build_environment: String,
    pub expected_package_name: String,
    pub policy_digest_sha256: String,
    pub runtime_policy: IntegrityRuntimePolicy,
    pub expected_certificate_sha256: Vec<String>,
    pub payload_version: String,
    pub payload_file_sha256: BTreeMap<String, String>,
    pub protected_asset_paths: BTreeMap<String, IntegrityProtectedAssetKind>,
    pub generated_by: IntegrityTool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityManifest {
    pub schema_version: u32,
    pub manifest_type: String,
    pub build_id: String,
    pub package_name: String,
    pub application: IntegrityApplication,
    pub policy: IntegrityPolicy,
    pub android: IntegrityAndroid,
    pub provider: IntegrityProvider,
    pub payload: IntegrityPayload,
    pub protected_assets: Vec<IntegrityProtectedAsset>,
    #[serde(default)]
    pub apk_inventory: IntegrityApkInventory,
    pub generated_by: IntegrityTool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityApplication {
    pub profile: String,
    pub build_environment: String,
    pub expected_package_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityPolicy {
    pub digest_sha256: String,
    #[serde(default = "default_runtime_policy")]
    pub runtime: IntegrityRuntimePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityRuntimePolicy {
    pub thresholds: IntegrityRiskThresholds,
    #[serde(default = "default_startup_budget_ms")]
    pub startup_budget_ms: u32,
    pub runtime_high_risk_action: IntegrityRiskAction,
    #[serde(default = "default_startup_integrity_action")]
    pub startup_integrity_action: IntegrityRiskAction,
    #[serde(default = "default_startup_payload_tampering_action")]
    pub startup_payload_tampering_action: IntegrityRiskAction,
    #[serde(default = "default_runtime_monitoring")]
    pub monitoring: IntegrityRuntimeMonitoring,
    #[serde(default = "default_runtime_detections")]
    pub detections: IntegrityRuntimeDetections,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityRuntimeMonitoring {
    pub enabled: bool,
    pub scan_interval_minimum_ms: u32,
    pub scan_interval_maximum_ms: u32,
    pub deep_scan_on_suspicion: bool,
    pub monitor_background_state: bool,
}

pub fn default_startup_budget_ms() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityRuntimeDetections {
    pub debugger: IntegrityDetectionRule,
    pub instrumentation: IntegrityDetectionRule,
    pub memory: IntegrityDetectionRule,
    pub root: IntegrityDetectionRule,
    pub emulator: IntegrityDetectionRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityDetectionRule {
    pub enabled: bool,
    pub weight: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityRiskThresholds {
    pub report: u8,
    pub warn: u8,
    pub restrict: u8,
    pub terminate: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityRiskAction {
    Allow,
    Report,
    Warn,
    LockStartup,
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityAndroid {
    pub expected_certificate_sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityProvider {
    pub name: String,
    pub authorities: String,
    pub exported: bool,
    pub init_order: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityPayload {
    pub version: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityProtectedAsset {
    pub path: String,
    pub sha256: String,
    pub kind: IntegrityProtectedAssetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IntegrityApkInventory {
    pub entry_count: usize,
    pub entry_set_sha256: String,
    pub executable_entry_count: usize,
    pub executable_entry_set_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityProtectedAssetKind {
    BootstrapDex,
    NativeLibrary,
    JavascriptBundle,
    FlutterAsset,
    FlutterNativeLibrary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedAssetObservation {
    sha256: String,
    kind: IntegrityProtectedAssetKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertedManifestProvider {
    pub name: String,
    pub authorities: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedApkRewriteReport {
    pub output_path: PathBuf,
    pub copied_entries: usize,
    pub skipped_signature_entries: Vec<String>,
    pub inserted_manifest_provider: InsertedManifestProvider,
    pub inserted_integrity_manifest_entry: String,
    pub inserted_dex_entry: String,
    pub inserted_native_library_entries: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApkRewriteError {
    #[error("failed to access APK or payload file: {0}")]
    Io(#[from] io::Error),
    #[error("invalid APK ZIP structure: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("failed to serialize integrity manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to mutate AndroidManifest.xml: {0}")]
    Manifest(#[from] android_axml::AxmlError),
    #[error("unsafe APK ZIP structure: {0}")]
    UnsafeZip(String),
    #[error("APK rewrite validation failed: {0}")]
    Validation(String),
}

pub fn is_zip_slip_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path.split('/').any(|segment| segment == "..")
        || path.split('\\').any(|segment| segment == "..")
}

pub fn rewrite_unsigned_apk_with_payload(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    payload_files: &PayloadFiles,
    rewrite_options: &ApkRewriteOptions,
) -> Result<UnsignedApkRewriteReport, ApkRewriteError> {
    let input = input.as_ref();
    let output = output.as_ref();

    validate_input_apk_path(input)?;
    validate_output_path(input, output)?;
    validate_payload_files(payload_files)?;
    validate_rewrite_options(rewrite_options)?;

    let input_file = File::open(input)?;
    let mut input_archive = ZipArchive::new(input_file)?;
    if input_archive.len() > MAX_APK_ENTRIES {
        return Err(ApkRewriteError::UnsafeZip(format!(
            "entry count {} exceeds limit {MAX_APK_ENTRIES}",
            input_archive.len()
        )));
    }

    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let temporary_output = temporary_output_path(output);
    let output_file = File::create(&temporary_output)?;
    let mut output_archive = ZipWriter::new(output_file);
    let mut seen_entries = BTreeSet::new();
    let mut dex_entries = BTreeSet::new();
    let mut inventory_entries = BTreeSet::new();
    let mut copied_entries = 0usize;
    let mut skipped_signature_entries = Vec::new();
    let mut inserted_manifest_provider = None;
    let mut package_name = None;
    let mut observed_protected_assets = BTreeMap::new();
    let mut total_uncompressed_bytes = 0u64;

    for index in 0..input_archive.len() {
        let mut entry = input_archive.by_index(index)?;
        let entry_name = entry.name().to_string();
        validate_apk_entry_name(&entry_name)?;

        if !seen_entries.insert(entry_name.clone()) {
            return Err(ApkRewriteError::UnsafeZip(format!(
                "duplicate ZIP path found: {entry_name}"
            )));
        }

        total_uncompressed_bytes = total_uncompressed_bytes.saturating_add(entry.size());
        if total_uncompressed_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(ApkRewriteError::UnsafeZip(format!(
                "total uncompressed size exceeds {} bytes",
                MAX_TOTAL_UNCOMPRESSED_BYTES
            )));
        }

        if entry.is_symlink() {
            return Err(ApkRewriteError::UnsafeZip(format!(
                "symbolic-link ZIP entries are not supported: {entry_name}"
            )));
        }

        if is_jar_signature_metadata_entry(&entry_name) {
            skipped_signature_entries.push(entry_name);
            continue;
        }

        if !entry.is_dir() {
            inventory_entries.insert(entry_name.clone());
        }

        if is_dex_entry(&entry_name) {
            dex_entries.insert(entry_name.clone());
        }

        if entry.is_dir() {
            output_archive.add_directory(entry_name, entry.options())?;
        } else if entry_name == ANDROID_MANIFEST_PATH {
            let entry_options = entry.options();
            let mut manifest_bytes = Vec::new();
            entry.read_to_end(&mut manifest_bytes)?;
            let parsed_manifest = parse_manifest(&manifest_bytes)?;
            let manifest_package_name = parsed_manifest.package_name.ok_or_else(|| {
                ApkRewriteError::Validation(
                    "AndroidManifest.xml is missing package name".to_string(),
                )
            })?;
            if manifest_package_name != rewrite_options.integrity_manifest.expected_package_name {
                return Err(ApkRewriteError::Validation(format!(
                    "AndroidManifest.xml package name {} does not match expected package {}",
                    manifest_package_name, rewrite_options.integrity_manifest.expected_package_name
                )));
            }
            let authorities =
                bootstrap_provider_authority(&manifest_package_name, &rewrite_options.build_id);
            let provider = ManifestProvider {
                name: android_dex::BOOTSTRAP_PROVIDER_CLASS.to_string(),
                authorities,
                exported: false,
                init_order: Some(rewrite_options.provider_init_order),
            };
            let mutated_manifest = inject_manifest_provider(&manifest_bytes, &provider)?;
            output_archive.start_file(entry_name, entry_options)?;
            output_archive.write_all(&mutated_manifest)?;
            inserted_manifest_provider = Some(InsertedManifestProvider {
                name: provider.name,
                authorities: provider.authorities,
            });
            package_name = Some(manifest_package_name);
        } else {
            let options = entry.options();
            output_archive.start_file(&entry_name, options)?;
            if let Some(kind) = rewrite_options
                .integrity_manifest
                .protected_asset_paths
                .get(&entry_name)
            {
                let sha256 = copy_with_sha256(&mut entry, &mut output_archive)?;
                observed_protected_assets.insert(
                    entry_name,
                    ProtectedAssetObservation {
                        sha256,
                        kind: *kind,
                    },
                );
            } else {
                io::copy(&mut entry, &mut output_archive)?;
            }
        }
        copied_entries += 1;
    }

    let inserted_manifest_provider = inserted_manifest_provider.ok_or_else(|| {
        ApkRewriteError::Validation("APK is missing AndroidManifest.xml".to_string())
    })?;
    let package_name = package_name
        .ok_or_else(|| ApkRewriteError::Validation("APK is missing package name".to_string()))?;
    for protected_asset_path in rewrite_options
        .integrity_manifest
        .protected_asset_paths
        .keys()
    {
        if !observed_protected_assets.contains_key(protected_asset_path) {
            return Err(ApkRewriteError::Validation(format!(
                "configured protected asset is missing from APK: {protected_asset_path}"
            )));
        }
    }

    let inserted_dex_entry = android_dex::next_dex_name_for_paths(dex_entries.iter());
    reject_entry_collision(&seen_entries, &inserted_dex_entry)?;
    inventory_entries.insert(inserted_dex_entry.clone());
    write_file_entry(
        &mut output_archive,
        &inserted_dex_entry,
        &payload_files.bootstrap_dex_path,
        CompressionMethod::Deflated,
    )?;

    let mut inserted_native_library_entries = Vec::new();
    for (abi, library_path) in &payload_files.abi_libraries {
        let entry_name = format!("lib/{abi}/{SECURITY_LIBRARY_NAME}");
        reject_entry_collision(&seen_entries, &entry_name)?;
        inventory_entries.insert(entry_name.clone());
        write_file_entry(
            &mut output_archive,
            &entry_name,
            library_path,
            CompressionMethod::Stored,
        )?;
        inserted_native_library_entries.push(entry_name);
    }

    reject_entry_collision(&seen_entries, INTEGRITY_MANIFEST_ENTRY)?;
    inventory_entries.insert(INTEGRITY_MANIFEST_ENTRY.to_string());
    let integrity_manifest = build_integrity_manifest(
        rewrite_options,
        package_name,
        &inserted_manifest_provider,
        &inserted_dex_entry,
        &inserted_native_library_entries,
        observed_protected_assets,
        apk_inventory_from_entries(&inventory_entries),
    )?;
    write_json_entry(
        &mut output_archive,
        INTEGRITY_MANIFEST_ENTRY,
        &integrity_manifest,
    )?;

    output_archive.finish()?;
    fs::rename(&temporary_output, output)?;

    Ok(UnsignedApkRewriteReport {
        output_path: output.to_path_buf(),
        copied_entries,
        skipped_signature_entries,
        inserted_manifest_provider,
        inserted_integrity_manifest_entry: INTEGRITY_MANIFEST_ENTRY.to_string(),
        inserted_dex_entry,
        inserted_native_library_entries,
    })
}

fn validate_input_apk_path(path: &Path) -> Result<(), ApkRewriteError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ApkRewriteError::Validation(format!(
            "input APK must not be a symbolic link: {}",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(ApkRewriteError::Validation(format!(
            "input APK must be a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_output_path(input: &Path, output: &Path) -> Result<(), ApkRewriteError> {
    if output.as_os_str().is_empty() {
        return Err(ApkRewriteError::Validation(
            "output APK path must not be empty".to_string(),
        ));
    }

    if output.exists() && fs::canonicalize(input)? == fs::canonicalize(output)? {
        return Err(ApkRewriteError::Validation(
            "input and output APK paths must be different".to_string(),
        ));
    }

    Ok(())
}

fn validate_payload_files(payload_files: &PayloadFiles) -> Result<(), ApkRewriteError> {
    if !payload_files.bootstrap_dex_path.is_file() {
        return Err(ApkRewriteError::Validation(format!(
            "bootstrap DEX does not exist: {}",
            payload_files.bootstrap_dex_path.display()
        )));
    }

    if payload_files.abi_libraries.is_empty() {
        return Err(ApkRewriteError::Validation(
            "payload must contain at least one native ABI library".to_string(),
        ));
    }

    for (abi, library_path) in &payload_files.abi_libraries {
        validate_abi_name(abi)?;
        if !library_path.is_file() {
            return Err(ApkRewriteError::Validation(format!(
                "payload native library for {abi} does not exist: {}",
                library_path.display()
            )));
        }
    }

    Ok(())
}

fn validate_rewrite_options(options: &ApkRewriteOptions) -> Result<(), ApkRewriteError> {
    if options.build_id.trim().is_empty() {
        return Err(ApkRewriteError::Validation(
            "build ID must not be empty".to_string(),
        ));
    }
    if !is_hex_sha256(&options.integrity_manifest.policy_digest_sha256) {
        return Err(ApkRewriteError::Validation(
            "policy digest must be a 64-character SHA-256 hex digest".to_string(),
        ));
    }
    validate_runtime_policy(&options.integrity_manifest.runtime_policy)?;
    if options
        .integrity_manifest
        .expected_certificate_sha256
        .is_empty()
    {
        return Err(ApkRewriteError::Validation(
            "integrity manifest must include at least one expected certificate digest".to_string(),
        ));
    }
    for digest in &options.integrity_manifest.expected_certificate_sha256 {
        if !is_hex_sha256(digest) {
            return Err(ApkRewriteError::Validation(format!(
                "expected certificate digest must be a 64-character SHA-256 hex digest: {digest}"
            )));
        }
    }
    if options.integrity_manifest.payload_version.trim().is_empty() {
        return Err(ApkRewriteError::Validation(
            "payload version must not be empty".to_string(),
        ));
    }
    for (path, digest) in &options.integrity_manifest.payload_file_sha256 {
        validate_apk_entry_name(path)?;
        if !is_hex_sha256(digest) {
            return Err(ApkRewriteError::Validation(format!(
                "payload file digest must be a 64-character SHA-256 hex digest for {path}"
            )));
        }
    }
    for path in options.integrity_manifest.protected_asset_paths.keys() {
        validate_apk_entry_name(path)?;
        if path == INTEGRITY_MANIFEST_ENTRY {
            return Err(ApkRewriteError::Validation(
                "integrity manifest cannot protect its own output entry".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_runtime_policy(policy: &IntegrityRuntimePolicy) -> Result<(), ApkRewriteError> {
    let thresholds = &policy.thresholds;
    if !(thresholds.report < thresholds.warn
        && thresholds.warn < thresholds.restrict
        && thresholds.restrict <= thresholds.terminate)
    {
        return Err(ApkRewriteError::Validation(
            "runtime policy thresholds must be ordered: report < warn < restrict <= terminate"
                .to_string(),
        ));
    }
    if policy.startup_budget_ms == 0 {
        return Err(ApkRewriteError::Validation(
            "runtime startup budget must be greater than zero".to_string(),
        ));
    }
    if policy.monitoring.scan_interval_minimum_ms == 0
        || policy.monitoring.scan_interval_minimum_ms > policy.monitoring.scan_interval_maximum_ms
    {
        return Err(ApkRewriteError::Validation(
            "runtime monitoring interval must be greater than zero and minimum <= maximum"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_abi_name(abi: &str) -> Result<(), ApkRewriteError> {
    if matches!(abi, "arm64-v8a" | "armeabi-v7a" | "x86_64") {
        Ok(())
    } else {
        Err(ApkRewriteError::Validation(format!(
            "unsupported payload ABI: {abi}"
        )))
    }
}

fn validate_apk_entry_name(entry_name: &str) -> Result<(), ApkRewriteError> {
    if entry_name.is_empty() || is_zip_slip_path(entry_name) {
        return Err(ApkRewriteError::UnsafeZip(format!(
            "unsafe ZIP path found: {entry_name}"
        )));
    }

    Ok(())
}

fn reject_entry_collision(
    existing_entries: &BTreeSet<String>,
    entry_name: &str,
) -> Result<(), ApkRewriteError> {
    if existing_entries.contains(entry_name) {
        Err(ApkRewriteError::Validation(format!(
            "payload output entry collides with existing APK entry: {entry_name}"
        )))
    } else {
        Ok(())
    }
}

fn build_integrity_manifest(
    rewrite_options: &ApkRewriteOptions,
    package_name: String,
    provider: &InsertedManifestProvider,
    inserted_dex_entry: &str,
    inserted_native_library_entries: &[String],
    observed_protected_assets: BTreeMap<String, ProtectedAssetObservation>,
    apk_inventory: IntegrityApkInventory,
) -> Result<IntegrityManifest, ApkRewriteError> {
    let input = &rewrite_options.integrity_manifest;
    let mut protected_assets = Vec::new();
    protected_assets.push(IntegrityProtectedAsset {
        path: inserted_dex_entry.to_string(),
        sha256: payload_digest(input, BOOTSTRAP_DEX_FILE)?,
        kind: IntegrityProtectedAssetKind::BootstrapDex,
    });

    for entry_name in inserted_native_library_entries {
        let abi = native_library_abi_from_entry(entry_name).ok_or_else(|| {
            ApkRewriteError::Validation(format!(
                "inserted native library path has unexpected shape: {entry_name}"
            ))
        })?;
        protected_assets.push(IntegrityProtectedAsset {
            path: entry_name.clone(),
            sha256: payload_digest(input, &format!("{abi}/{SECURITY_LIBRARY_NAME}"))?,
            kind: IntegrityProtectedAssetKind::NativeLibrary,
        });
    }

    for (path, observation) in observed_protected_assets {
        protected_assets.push(IntegrityProtectedAsset {
            path,
            sha256: observation.sha256,
            kind: observation.kind,
        });
    }

    protected_assets.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
    });

    Ok(IntegrityManifest {
        schema_version: INTEGRITY_MANIFEST_SCHEMA_VERSION,
        manifest_type: "RASP_SHIELD_ANDROID_INTEGRITY".to_string(),
        build_id: rewrite_options.build_id.clone(),
        package_name,
        application: IntegrityApplication {
            profile: input.application_profile.clone(),
            build_environment: input.build_environment.clone(),
            expected_package_name: input.expected_package_name.clone(),
        },
        policy: IntegrityPolicy {
            digest_sha256: input.policy_digest_sha256.clone(),
            runtime: input.runtime_policy.clone(),
        },
        android: IntegrityAndroid {
            expected_certificate_sha256: input.expected_certificate_sha256.clone(),
        },
        provider: IntegrityProvider {
            name: provider.name.clone(),
            authorities: provider.authorities.clone(),
            exported: false,
            init_order: Some(rewrite_options.provider_init_order),
        },
        payload: IntegrityPayload {
            version: input.payload_version.clone(),
            files: input.payload_file_sha256.clone(),
        },
        protected_assets,
        apk_inventory,
        generated_by: input.generated_by.clone(),
    })
}

fn apk_inventory_from_entries(entries: &BTreeSet<String>) -> IntegrityApkInventory {
    let executable_entries = entries
        .iter()
        .filter(|entry| is_executable_inventory_entry(entry))
        .cloned()
        .collect::<BTreeSet<_>>();

    IntegrityApkInventory {
        entry_count: entries.len(),
        entry_set_sha256: path_set_digest(entries),
        executable_entry_count: executable_entries.len(),
        executable_entry_set_sha256: path_set_digest(&executable_entries),
    }
}

fn path_set_digest(paths: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(path.as_bytes());
        hasher.update([0]);
    }
    hex_lower(&hasher.finalize())
}

fn payload_digest(input: &IntegrityManifestInput, path: &str) -> Result<String, ApkRewriteError> {
    input.payload_file_sha256.get(path).cloned().ok_or_else(|| {
        ApkRewriteError::Validation(format!(
            "payload manifest is missing digest for protected payload file {path}"
        ))
    })
}

fn native_library_abi_from_entry(entry_name: &str) -> Option<&str> {
    entry_name
        .strip_prefix("lib/")
        .and_then(|value| value.strip_suffix(&format!("/{SECURITY_LIBRARY_NAME}")))
}

fn copy_with_sha256(
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<String, ApkRewriteError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        output.write_all(&buffer[..bytes_read])?;
    }

    Ok(hex_lower(&hasher.finalize()))
}

fn write_json_entry(
    output_archive: &mut ZipWriter<File>,
    entry_name: &str,
    value: &impl Serialize,
) -> Result<(), ApkRewriteError> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644);
    output_archive.start_file(entry_name, options)?;
    let body = serde_json::to_vec_pretty(value)?;
    output_archive.write_all(&body)?;
    output_archive.write_all(b"\n")?;
    Ok(())
}

fn write_file_entry(
    output_archive: &mut ZipWriter<File>,
    entry_name: &str,
    source_path: &Path,
    compression_method: CompressionMethod,
) -> Result<(), ApkRewriteError> {
    let options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .unix_permissions(0o644);
    output_archive.start_file(entry_name, options)?;
    let mut source_file = File::open(source_path)?;
    io::copy(&mut source_file, output_archive)?;
    Ok(())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn temporary_output_path(output: &Path) -> PathBuf {
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output.apk");
    output.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()))
}

fn is_dex_entry(path: &str) -> bool {
    if path == "classes.dex" {
        return true;
    }

    let Some(suffix) = path
        .strip_prefix("classes")
        .and_then(|value| value.strip_suffix(".dex"))
    else {
        return false;
    };

    !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
}

fn is_executable_inventory_entry(path: &str) -> bool {
    is_dex_entry(path)
        || is_native_library_entry(path)
        || path.ends_with(".dex")
        || path.ends_with(".jar")
        || path.ends_with(".apk")
        || path.ends_with(".so")
}

fn is_native_library_entry(path: &str) -> bool {
    let mut parts = path.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("lib"), Some(_), Some(name), None) if name.ends_with(".so")
    )
}

fn is_jar_signature_metadata_entry(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    upper == SIGNATURE_MANIFEST_ENTRY
        || upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA")
                || upper.ends_with(".DSA")
                || upper.ends_with(".EC")
                || upper.ends_with(".SF"))
}

#[cfg(test)]
mod tests {
    use super::{
        default_runtime_detections, hex_lower, is_jar_signature_metadata_entry, is_zip_slip_path,
        rewrite_unsigned_apk_with_payload, ApkRewriteOptions, IntegrityManifest,
        IntegrityManifestInput, IntegrityProtectedAssetKind, IntegrityRiskAction,
        IntegrityRiskThresholds, IntegrityRuntimeMonitoring, IntegrityRuntimePolicy, IntegrityTool,
        PayloadFiles, INTEGRITY_MANIFEST_ENTRY,
    };
    use android_axml::{bootstrap_provider_authority, parse_manifest};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    #[test]
    fn detects_zip_slip_paths() {
        assert!(is_zip_slip_path("../AndroidManifest.xml"));
        assert!(is_zip_slip_path("assets/../../secret"));
        assert!(is_zip_slip_path("/absolute/path"));
        assert!(!is_zip_slip_path("assets/index.android.bundle"));
    }

    #[test]
    fn identifies_jar_signature_metadata_entries() {
        assert!(is_jar_signature_metadata_entry("META-INF/MANIFEST.MF"));
        assert!(is_jar_signature_metadata_entry("META-INF/CERT.SF"));
        assert!(is_jar_signature_metadata_entry("META-INF/CERT.RSA"));
        assert!(is_jar_signature_metadata_entry("META-INF/CERT.DSA"));
        assert!(is_jar_signature_metadata_entry("META-INF/CERT.EC"));
        assert!(!is_jar_signature_metadata_entry("META-INF/LICENSE.txt"));
    }

    #[test]
    fn rewrites_unsigned_apk_with_payload_entries() {
        let root = create_temp_dir("rewrite");
        let input_apk = root.join("input.apk");
        let output_apk = root.join("output.apk");
        create_test_apk(&input_apk);

        let bootstrap_dex_path = root.join("bootstrap.dex");
        let native_library_path = root.join("libsecurity.so");
        fs::write(&bootstrap_dex_path, b"payload dex").expect("write bootstrap dex");
        fs::write(&native_library_path, b"payload so").expect("write native library");

        let payload = PayloadFiles {
            bootstrap_dex_path,
            abi_libraries: BTreeMap::from([("arm64-v8a".to_string(), native_library_path)]),
        };
        let rewrite_options = rewrite_options();
        let expected_authorities =
            bootstrap_provider_authority("com.example.mobile", &rewrite_options.build_id);

        let report =
            rewrite_unsigned_apk_with_payload(&input_apk, &output_apk, &payload, &rewrite_options)
                .expect("rewrite");

        assert_eq!(report.inserted_dex_entry, "classes3.dex");
        assert_eq!(
            report.inserted_manifest_provider.name,
            android_dex::BOOTSTRAP_PROVIDER_CLASS
        );
        assert_eq!(
            report.inserted_manifest_provider.authorities,
            expected_authorities
        );
        assert_eq!(
            report.inserted_native_library_entries,
            vec!["lib/arm64-v8a/libsecurity.so"]
        );
        assert_eq!(
            report.inserted_integrity_manifest_entry,
            INTEGRITY_MANIFEST_ENTRY
        );
        assert_eq!(
            report.skipped_signature_entries,
            vec![
                "META-INF/MANIFEST.MF",
                "META-INF/CERT.SF",
                "META-INF/CERT.RSA"
            ]
        );

        let mut archive =
            ZipArchive::new(File::open(output_apk).expect("open output")).expect("read output APK");
        assert_eq!(read_zip_entry(&mut archive, "classes.dex"), b"base dex");
        assert_eq!(read_zip_entry(&mut archive, "classes2.dex"), b"second dex");
        assert_eq!(read_zip_entry(&mut archive, "classes3.dex"), b"payload dex");
        let manifest = parse_manifest(&read_zip_entry(&mut archive, "AndroidManifest.xml"))
            .expect("parse output manifest");
        assert!(manifest.providers.iter().any(|provider| {
            provider.name.as_deref() == Some(android_dex::BOOTSTRAP_PROVIDER_CLASS)
                && provider.authorities.as_deref() == Some(expected_authorities.as_str())
                && provider.exported == Some(false)
        }));
        assert_eq!(
            read_zip_entry(&mut archive, "lib/arm64-v8a/libsecurity.so"),
            b"payload so"
        );
        assert_eq!(
            archive
                .by_name("lib/arm64-v8a/libsecurity.so")
                .expect("native entry")
                .compression(),
            CompressionMethod::Stored
        );
        assert!(archive.by_name("assets/index.android.bundle").is_ok());
        let integrity_manifest: IntegrityManifest =
            serde_json::from_slice(&read_zip_entry(&mut archive, INTEGRITY_MANIFEST_ENTRY))
                .expect("parse integrity manifest");
        assert_eq!(integrity_manifest.schema_version, 1);
        assert_eq!(integrity_manifest.build_id, rewrite_options.build_id);
        assert_eq!(integrity_manifest.package_name, "com.example.mobile");
        assert_eq!(
            integrity_manifest.provider.authorities,
            expected_authorities
        );
        assert_eq!(
            integrity_manifest.payload.files["bootstrap.dex"],
            "1".repeat(64)
        );
        assert_eq!(integrity_manifest.policy.runtime.thresholds.report, 20);
        assert_eq!(integrity_manifest.policy.runtime.startup_budget_ms, 50);
        assert_eq!(integrity_manifest.apk_inventory.entry_count, 9);
        assert_eq!(integrity_manifest.apk_inventory.executable_entry_count, 5);
        assert_eq!(integrity_manifest.apk_inventory.entry_set_sha256.len(), 64);
        assert_eq!(
            integrity_manifest
                .apk_inventory
                .executable_entry_set_sha256
                .len(),
            64
        );
        assert_eq!(
            integrity_manifest.policy.runtime.runtime_high_risk_action,
            IntegrityRiskAction::Report
        );
        assert_eq!(
            integrity_manifest.policy.runtime.startup_integrity_action,
            IntegrityRiskAction::Terminate
        );
        assert_eq!(
            integrity_manifest
                .policy
                .runtime
                .startup_payload_tampering_action,
            IntegrityRiskAction::Terminate
        );
        assert!(integrity_manifest.policy.runtime.monitoring.enabled);
        assert!(
            integrity_manifest
                .policy
                .runtime
                .detections
                .debugger
                .enabled
        );
        assert_eq!(
            integrity_manifest.policy.runtime.detections.debugger.weight,
            40
        );
        assert!(
            integrity_manifest
                .policy
                .runtime
                .detections
                .instrumentation
                .enabled
        );
        assert_eq!(
            integrity_manifest
                .policy
                .runtime
                .detections
                .instrumentation
                .weight,
            60
        );
        assert!(integrity_manifest.policy.runtime.detections.memory.enabled);
        assert_eq!(
            integrity_manifest.policy.runtime.detections.memory.weight,
            60
        );
        assert_eq!(
            integrity_manifest
                .policy
                .runtime
                .monitoring
                .scan_interval_minimum_ms,
            5_000
        );
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == "classes3.dex"
                && asset.sha256 == "1".repeat(64)
                && asset.kind == IntegrityProtectedAssetKind::BootstrapDex
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == "lib/arm64-v8a/libsecurity.so"
                && asset.sha256 == "2".repeat(64)
                && asset.kind == IntegrityProtectedAssetKind::NativeLibrary
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == "assets/index.android.bundle"
                && asset.sha256 == sha256_bytes(b"bundle")
                && asset.kind == IntegrityProtectedAssetKind::JavascriptBundle
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == "assets/flutter_assets/AssetManifest.json"
                && asset.sha256 == sha256_bytes(b"{}")
                && asset.kind == IntegrityProtectedAssetKind::FlutterAsset
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == "lib/arm64-v8a/libapp.so"
                && asset.sha256 == sha256_bytes(b"flutter app")
                && asset.kind == IntegrityProtectedAssetKind::FlutterNativeLibrary
        }));
        assert!(archive.by_name("META-INF/CERT.RSA").is_err());
    }

    #[test]
    fn rejects_payload_entry_collisions() {
        let root = create_temp_dir("collision");
        let input_apk = root.join("input.apk");
        let output_apk = root.join("output.apk");
        let manifest = minimal_manifest("com.example.mobile");
        create_apk_with_entries(
            &input_apk,
            &[
                ("AndroidManifest.xml", manifest),
                ("classes.dex", b"base dex".to_vec()),
                ("assets/index.android.bundle", b"bundle".to_vec()),
                ("assets/flutter_assets/AssetManifest.json", b"{}".to_vec()),
                ("lib/arm64-v8a/libapp.so", b"flutter app".to_vec()),
                ("lib/arm64-v8a/libsecurity.so", b"existing".to_vec()),
            ],
        );

        let bootstrap_dex_path = root.join("bootstrap.dex");
        let native_library_path = root.join("libsecurity.so");
        fs::write(&bootstrap_dex_path, b"payload dex").expect("write bootstrap dex");
        fs::write(&native_library_path, b"payload so").expect("write native library");

        let payload = PayloadFiles {
            bootstrap_dex_path,
            abi_libraries: BTreeMap::from([("arm64-v8a".to_string(), native_library_path)]),
        };

        let error = rewrite_unsigned_apk_with_payload(
            &input_apk,
            &output_apk,
            &payload,
            &rewrite_options(),
        )
        .expect_err("collision should fail");

        assert!(error
            .to_string()
            .contains("collides with existing APK entry"));
    }

    fn create_test_apk(path: &PathBuf) {
        let manifest = minimal_manifest("com.example.mobile");
        create_apk_with_entries(
            path,
            &[
                ("AndroidManifest.xml", manifest),
                ("classes.dex", b"base dex".to_vec()),
                ("classes2.dex", b"second dex".to_vec()),
                ("assets/index.android.bundle", b"bundle".to_vec()),
                ("assets/flutter_assets/AssetManifest.json", b"{}".to_vec()),
                ("lib/arm64-v8a/libapp.so", b"flutter app".to_vec()),
                ("META-INF/MANIFEST.MF", b"manifest signature".to_vec()),
                ("META-INF/CERT.SF", b"sf signature".to_vec()),
                ("META-INF/CERT.RSA", b"rsa signature".to_vec()),
            ],
        );
    }

    fn create_apk_with_entries(path: &PathBuf, entries: &[(&str, Vec<u8>)]) {
        let file = File::create(path).expect("create APK");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            writer.start_file(name, options).expect("start entry");
            writer.write_all(bytes).expect("write entry");
        }
        writer.finish().expect("finish APK");
    }

    fn read_zip_entry(archive: &mut ZipArchive<File>, name: &str) -> Vec<u8> {
        let mut entry = archive.by_name(name).expect("entry exists");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("read entry");
        bytes
    }

    fn rewrite_options() -> ApkRewriteOptions {
        ApkRewriteOptions {
            build_id: "a91f30c2d41e8bf0d9d8f3e14a47d2e4a9c3617e57df9b36f9fcff1977b8b18a"
                .to_string(),
            provider_init_order: 1000,
            integrity_manifest: IntegrityManifestInput {
                application_profile: "test".to_string(),
                build_environment: "development".to_string(),
                expected_package_name: "com.example.mobile".to_string(),
                policy_digest_sha256: "0".repeat(64),
                runtime_policy: IntegrityRuntimePolicy {
                    thresholds: IntegrityRiskThresholds {
                        report: 20,
                        warn: 40,
                        restrict: 70,
                        terminate: 100,
                    },
                    startup_budget_ms: 50,
                    runtime_high_risk_action: IntegrityRiskAction::Report,
                    startup_integrity_action: IntegrityRiskAction::Terminate,
                    startup_payload_tampering_action: IntegrityRiskAction::Terminate,
                    monitoring: IntegrityRuntimeMonitoring {
                        enabled: true,
                        scan_interval_minimum_ms: 5_000,
                        scan_interval_maximum_ms: 15_000,
                        deep_scan_on_suspicion: true,
                        monitor_background_state: false,
                    },
                    detections: default_runtime_detections(),
                },
                expected_certificate_sha256: vec!["a".repeat(64)],
                payload_version: "test-payload".to_string(),
                payload_file_sha256: BTreeMap::from([
                    ("bootstrap.dex".to_string(), "1".repeat(64)),
                    ("arm64-v8a/libsecurity.so".to_string(), "2".repeat(64)),
                ]),
                protected_asset_paths: BTreeMap::from([
                    (
                        "assets/index.android.bundle".to_string(),
                        IntegrityProtectedAssetKind::JavascriptBundle,
                    ),
                    (
                        "assets/flutter_assets/AssetManifest.json".to_string(),
                        IntegrityProtectedAssetKind::FlutterAsset,
                    ),
                    (
                        "lib/arm64-v8a/libapp.so".to_string(),
                        IntegrityProtectedAssetKind::FlutterNativeLibrary,
                    ),
                ]),
                generated_by: IntegrityTool {
                    name: "rasp-cli".to_string(),
                    version: "0.1.0".to_string(),
                },
            },
        }
    }

    fn create_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rasp-android-apk-{name}-{nonce}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }

    fn minimal_manifest(package_name: &str) -> Vec<u8> {
        const RES_XML_TYPE: u16 = 0x0003;
        const RES_STRING_POOL_TYPE: u16 = 0x0001;
        const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
        const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
        const UTF8_FLAG: u32 = 0x0000_0100;
        const NO_INDEX: u32 = 0xffff_ffff;
        const TYPE_STRING: u8 = 0x03;

        let strings = vec!["manifest", "application", "package", package_name];
        let string_pool = build_test_string_pool(&strings, RES_STRING_POOL_TYPE, UTF8_FLAG);
        let manifest_index = test_string_index(&strings, "manifest");
        let application_index = test_string_index(&strings, "application");
        let package_index = test_string_index(&strings, "package");
        let package_value_index = test_string_index(&strings, package_name);

        let mut body = Vec::new();
        body.extend_from_slice(&string_pool);
        body.extend_from_slice(&build_test_start_element(
            RES_XML_START_ELEMENT_TYPE,
            NO_INDEX,
            TYPE_STRING,
            manifest_index,
            &[(
                NO_INDEX,
                package_index,
                package_value_index,
                TYPE_STRING,
                package_value_index,
            )],
        ));
        body.extend_from_slice(&build_test_start_element(
            RES_XML_START_ELEMENT_TYPE,
            NO_INDEX,
            TYPE_STRING,
            application_index,
            &[],
        ));
        body.extend_from_slice(&build_test_end_element(
            RES_XML_END_ELEMENT_TYPE,
            NO_INDEX,
            application_index,
        ));
        body.extend_from_slice(&build_test_end_element(
            RES_XML_END_ELEMENT_TYPE,
            NO_INDEX,
            manifest_index,
        ));

        let mut output = Vec::new();
        write_u16(&mut output, RES_XML_TYPE);
        write_u16(&mut output, 8);
        write_u32(&mut output, (8 + body.len()) as u32);
        output.extend_from_slice(&body);
        output
    }

    fn build_test_string_pool(strings: &[&str], chunk_type: u16, flags: u32) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut data = Vec::new();
        for value in strings {
            offsets.push(data.len() as u32);
            encode_test_length8(&mut data, value.encode_utf16().count());
            encode_test_length8(&mut data, value.len());
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }

        let strings_start = 28 + strings.len() * 4;
        let size = strings_start + data.len();
        let mut output = Vec::new();
        write_u16(&mut output, chunk_type);
        write_u16(&mut output, 28);
        write_u32(&mut output, size as u32);
        write_u32(&mut output, strings.len() as u32);
        write_u32(&mut output, 0);
        write_u32(&mut output, flags);
        write_u32(&mut output, strings_start as u32);
        write_u32(&mut output, 0);
        for offset in offsets {
            write_u32(&mut output, offset);
        }
        output.extend_from_slice(&data);
        output
    }

    fn build_test_start_element(
        chunk_type: u16,
        no_index: u32,
        _type_string: u8,
        name_index: u32,
        attributes: &[(u32, u32, u32, u8, u32)],
    ) -> Vec<u8> {
        let size = 36 + attributes.len() * 20;
        let mut output = Vec::new();
        write_u16(&mut output, chunk_type);
        write_u16(&mut output, 16);
        write_u32(&mut output, size as u32);
        write_u32(&mut output, 0);
        write_u32(&mut output, no_index);
        write_u32(&mut output, no_index);
        write_u32(&mut output, name_index);
        write_u16(&mut output, 20);
        write_u16(&mut output, 20);
        write_u16(&mut output, attributes.len() as u16);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        write_u16(&mut output, 0);
        for (namespace_index, attribute_name_index, raw_value_index, value_type, value_data) in
            attributes
        {
            write_u32(&mut output, *namespace_index);
            write_u32(&mut output, *attribute_name_index);
            write_u32(&mut output, *raw_value_index);
            write_u16(&mut output, 8);
            output.push(0);
            output.push(*value_type);
            write_u32(&mut output, *value_data);
        }
        output
    }

    fn build_test_end_element(chunk_type: u16, no_index: u32, name_index: u32) -> Vec<u8> {
        let mut output = Vec::new();
        write_u16(&mut output, chunk_type);
        write_u16(&mut output, 16);
        write_u32(&mut output, 24);
        write_u32(&mut output, 0);
        write_u32(&mut output, no_index);
        write_u32(&mut output, no_index);
        write_u32(&mut output, name_index);
        output
    }

    fn encode_test_length8(output: &mut Vec<u8>, length: usize) {
        if length <= 0x7f {
            output.push(length as u8);
        } else {
            output.push(((length >> 8) as u8) | 0x80);
            output.push((length & 0xff) as u8);
        }
    }

    fn test_string_index(strings: &[&str], value: &str) -> u32 {
        strings
            .iter()
            .position(|existing| *existing == value)
            .expect("string exists") as u32
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }

    fn write_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }
}
