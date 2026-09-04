use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use android_axml::{
    bootstrap_provider_authority, inject_manifest_provider, parse_manifest, ManifestProvider,
    ManifestProviderMetadata,
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
const BOOTSTRAP_RUNTIME_DEX_FILE: &str = "bootstrap-runtime.dex";
const BOOTSTRAP_RUNTIME_ENCRYPTION: &str = "XOR_SHA256_STREAM_V1";
const BOOTSTRAP_RUNTIME_KEY_DOMAIN: &str = "RASP_SHIELD_BOOTSTRAP_RUNTIME_V1";
const PAYLOAD_SECURITY_LIBRARY_NAME: &str = "libsecurity.so";
const DEFAULT_NATIVE_LIBRARY_NAME: &str = "security";
const DEFAULT_INTEGRITY_MANIFEST_ENTRY: &str = "assets/rasp-shield/integrity-manifest.json";
const BOOTSTRAP_LOADER_SOURCE_XOR_KEY: u8 = 0x5a;
const BOOTSTRAP_LOADER_BUILD_KEY_STRINGS: &[&str] = &[
    "XOR_SHA256_STREAM_V1",
    "RASP_SHIELD_BOOTSTRAP_RUNTIME_V1",
    "onProviderCreate",
    "startup_budget_ms",
    "startup_payload_tampering_action",
    "policy",
    "runtime",
    "payload",
    "encrypted_runtime",
    "asset_path",
    "class_name",
    "sha256",
    "encryption",
];
const NATIVE_SOURCE_XOR_KEY: u8 = 0x5a;
const NATIVE_BOOTSTRAP_XOR_KEY_MARKER: &[u8] = &[0x71, 0x49, NATIVE_SOURCE_XOR_KEY, 0xc5, 0x2d];
const NATIVE_DETECTOR_XOR_KEY_MARKER: &[u8] = &[0x29, 0x73, NATIVE_SOURCE_XOR_KEY, 0xb6, 0x4c];
const NATIVE_BOOTSTRAP_XOR_KEY_INDEX: usize = 2;
const NATIVE_BOOTSTRAP_METHOD_NAMES: &[&str] = &[
    "nativeInitialize",
    "nativeMonitorScan",
    "nativeLastActionCode",
    "nativeLastReportJson",
];
const NATIVE_DETECTOR_STRINGS: &[&str] = &[
    "frida",
    "gum-js-loop",
    "frida-agent",
    "frida-gadget",
    "linjector",
    "re.frida",
    "gum-js",
    "libfrida",
    "xposed",
    "lsposed",
    "edxposed",
    "sandhook",
    "yahahfa",
    "epic",
    "substrate",
    "cydia_substrate",
    "libsubstrate",
    "zygisk",
    "riru",
    "magisk",
    "dobby",
    "shadowhook",
    "xhook",
    "whale",
    "libhooker",
    "hookzz",
    "pool-frida",
    "frida-helper",
    "frida-dbgsignal",
    "gmain",
    "gdbus",
    "LD_PRELOAD",
    "generic",
    "sdk_gphone",
    "google_sdk",
    "emulator",
    "goldfish",
    "ranchu",
    "vbox",
    "virtualbox",
    "genymotion",
    "nox",
    "de/robv/android/xposed/XposedBridge",
    "org/lsposed/lspd/nativebridge/NativeAPI",
    "com/saurik/substrate/MS",
    "instrumentation",
    "debugger",
    "memory",
    "integrity",
    "root",
    "startup.",
    "startup.payload_",
    "startup.protected_asset_",
    "runtime.protected_asset_",
    "debugger.dumpable_lock_failed",
    "startup.package_mismatch",
    "startup.certificate_mismatch",
    "startup.payload_integrity_mismatch",
    "startup.protected_asset_mismatch",
    "runtime.protected_asset_mismatch",
    "instrumentation.frida_library",
    "instrumentation.xposed_framework",
    "instrumentation.substrate_framework",
    "instrumentation.zygisk_module",
    "instrumentation.native_hook_framework",
    "memory.writable_executable_map",
    "memory.deleted_executable_library",
    "memory.anonymous_executable_map",
    "instrumentation.frida_thread",
    "instrumentation.glib_thread",
    "instrumentation.frida_file_descriptor",
    "debugger.tracer_pid",
    "instrumentation.frida_default_port",
    "instrumentation.frida_unix_socket",
    "instrumentation.suspicious_environment",
    "integrity.native_text_modified",
    "root.su_binary",
    "root.magisk_path",
    "root.superuser_artifact",
    "root.test_keys",
    "root.debuggable_build",
    "root.insecure_system_property",
    "root.adb_root",
    "root.verified_boot_untrusted",
    "root.bootloader_unlocked",
    "root.writable_system_partition",
    "emulator.build_profile",
    "emulator.qemu_property",
    "emulator.qemu_file",
    "emulator.cpuinfo",
    "instrumentation.xposed_java_class",
    "instrumentation.lsposed_java_class",
    "instrumentation.substrate_java_class",
    "no active signals",
    "payload integrity mismatch",
    "startup identity integrity mismatch",
    "risk below report threshold",
    "risk reached runtime high-risk threshold",
    "risk reached warn threshold",
    "risk reached report threshold",
    "ALLOW",
    "REPORT",
    "WARN",
    "LOCK_STARTUP",
    "TERMINATE",
    "{\"detector_version\":",
    ",\"risk_score\":",
    ",\"action\":",
    ",\"action_reason\":",
    ",\"signals\":[",
    "{\"id\":",
    ",\"category\":",
    ",\"confidence\":",
    ",\"severity\":",
    ",\"weight\":",
    ",\"evidence\":",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/task",
    "/proc/self/fd",
    "/proc/net/tcp",
    "/proc/net/tcp6",
    "/proc/net/unix",
    "/proc/self/environ",
    "(Landroid/content/Context;IIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIIIIIIIIIIII)I",
    "(IIIILjava/lang/String;Ljava/lang/String;IIIIIIIIIII)I",
    "()Ljava/lang/String;",
    "Ljava/lang/String;",
    "%llx-%llx %4s",
    "%llx-%llx %4s %llx %15s %llu %511[^\n]",
    "[vdso]",
    "[vvar]",
    "dalvik",
    "boot.oat",
    "boot.art",
    "(deleted)",
    "00:00",
    "memfd:",
    "%s/%s",
    "%s/%s/comm",
    "%s=%s",
    "%127s %127s %63s %255s",
    "\\u%04x",
    "prctl(PR_SET_DUMPABLE)",
    "package name mismatch",
    "signing certificate mismatch",
    "payload asset digest mismatch",
    "protected asset digest mismatch",
    "rwx mapping",
    "deleted executable library mapping",
    "anonymous executable mapping",
    "TracerPid",
    "tcp:27042",
    "tcp:27043",
    "native text changed",
    "java hook bridge",
    "java hook native bridge",
    "java hook class",
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/vendor/bin/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/data/local/su",
    "/system/bin/.ext/.su",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/sbin/.magisk",
    "/debug_ramdisk/magisk",
    "/cache/magisk.log",
    "/system/app/Superuser.apk",
    "/system/etc/init.d/99SuperSUDaemon",
    "/dev/com.koushikdutta.superuser.daemon",
    "ro.build.tags",
    "ro.debuggable",
    "ro.secure",
    "service.adb.root",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state",
    "test-keys",
    "orange",
    "red",
    "unlocked",
    "/system",
    "/vendor",
    "/product",
    "/system_ext",
    "/odm",
    "/proc/mounts",
    "/proc/cpuinfo",
    "/dev/qemu_pipe",
    "/dev/qemu_trace",
    "/dev/goldfish_pipe",
    "/dev/socket/qemud",
    "/dev/socket/baseband_genyd",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "ro.kernel.qemu",
    "ro.boot.qemu",
    "ro.hardware",
    "ro.product.board",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.name",
    "android/os/Build",
    "BOARD",
    "BOOTLOADER",
    "BRAND",
    "DEVICE",
    "FINGERPRINT",
    "HARDWARE",
    "MANUFACTURER",
    "MODEL",
    "PRODUCT",
];
pub const INTEGRITY_MANIFEST_ENTRY: &str = DEFAULT_INTEGRITY_MANIFEST_ENTRY;
pub const INTEGRITY_MANIFEST_SCHEMA_VERSION: u32 = 1;

pub fn default_native_library_name() -> String {
    DEFAULT_NATIVE_LIBRARY_NAME.to_string()
}

pub fn native_library_name_for_build_id(build_id: &str) -> Result<String, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(
            "build ID must be a 64-character SHA-256 hex digest".to_string(),
        ));
    }
    Ok(format!("rs{}", build_id[..12].to_ascii_lowercase()))
}

pub fn integrity_manifest_entry_for_build_id(build_id: &str) -> Result<String, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(
            "build ID must be a 64-character SHA-256 hex digest".to_string(),
        ));
    }
    Ok(format!(
        "assets/r/{}/m",
        build_id[..12].to_ascii_lowercase()
    ))
}

pub fn encrypted_runtime_entry_for_build_id(build_id: &str) -> Result<String, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(
            "build ID must be a 64-character SHA-256 hex digest".to_string(),
        ));
    }
    Ok(format!(
        "assets/r/{}/d",
        build_id[..12].to_ascii_lowercase()
    ))
}

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
    pub bootstrap_runtime_dex_path: Option<PathBuf>,
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
    #[serde(default = "default_native_library_name")]
    pub native_library_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_runtime: Option<IntegrityEncryptedRuntime>,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityEncryptedRuntime {
    pub asset_path: String,
    pub class_name: String,
    pub sha256: String,
    pub encryption: String,
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
    BootstrapRuntimeDex,
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

#[derive(Debug, Clone, Copy)]
struct InsertedPayloadEntries<'a> {
    provider: &'a InsertedManifestProvider,
    native_library_name: &'a str,
    dex_entry: &'a InsertedPayloadEntry,
    runtime_dex_entry: Option<&'a InsertedPayloadEntry>,
    runtime_class: Option<&'a str>,
    native_library_entries: &'a [InsertedPayloadEntry],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InsertedPayloadEntry {
    apk_path: String,
    payload_path: String,
    sha256: String,
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
    pub inserted_runtime_dex_entry: Option<String>,
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
    let provider_class =
        android_dex::bootstrap_provider_class_for_build_id(&rewrite_options.build_id)
            .map_err(ApkRewriteError::Validation)?;
    let runtime_class =
        android_dex::bootstrap_runtime_class_for_build_id(&rewrite_options.build_id)
            .map_err(ApkRewriteError::Validation)?;
    let native_library_name = native_library_name_for_build_id(&rewrite_options.build_id)?;
    let integrity_manifest_entry =
        integrity_manifest_entry_for_build_id(&rewrite_options.build_id)?;
    if rewrite_options
        .integrity_manifest
        .protected_asset_paths
        .contains_key(&integrity_manifest_entry)
    {
        return Err(ApkRewriteError::Validation(
            "integrity manifest cannot protect its own output entry".to_string(),
        ));
    }
    let integrity_manifest_asset_path =
        integrity_manifest_asset_path_from_entry(&integrity_manifest_entry).ok_or_else(|| {
            ApkRewriteError::Validation(format!(
                "integrity manifest entry has unexpected path shape: {integrity_manifest_entry}"
            ))
        })?;
    let manifest_asset_metadata_name =
        bootstrap_manifest_asset_metadata_name_for_build_id(&rewrite_options.build_id)?;

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
                name: provider_class.clone(),
                authorities,
                exported: false,
                init_order: Some(rewrite_options.provider_init_order),
                meta_data: vec![ManifestProviderMetadata {
                    name: manifest_asset_metadata_name.clone(),
                    value: integrity_manifest_asset_path.clone(),
                }],
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

    let inserted_dex_apk_path = android_dex::next_dex_name_for_paths(dex_entries.iter());
    reject_entry_collision(&seen_entries, &inserted_dex_apk_path)?;
    inventory_entries.insert(inserted_dex_apk_path.clone());
    let patched_bootstrap_dex = patched_bootstrap_dex(
        &payload_files.bootstrap_dex_path,
        &provider_class,
        &rewrite_options.build_id,
    )?;
    let inserted_dex_entry = InsertedPayloadEntry {
        apk_path: inserted_dex_apk_path.clone(),
        payload_path: BOOTSTRAP_DEX_FILE.to_string(),
        sha256: sha256_bytes(&patched_bootstrap_dex),
    };
    write_bytes_entry(
        &mut output_archive,
        &inserted_dex_apk_path,
        &patched_bootstrap_dex,
        CompressionMethod::Deflated,
    )?;

    let mut inserted_runtime_dex_entry = None;
    let mut inserted_runtime_dex_path = None;
    if let Some(runtime_dex_path) = &payload_files.bootstrap_runtime_dex_path {
        let encrypted_runtime_apk_path =
            encrypted_runtime_entry_for_build_id(&rewrite_options.build_id)?;
        reject_entry_collision(&seen_entries, &encrypted_runtime_apk_path)?;
        inventory_entries.insert(encrypted_runtime_apk_path.clone());
        let encrypted_runtime_asset_path = integrity_manifest_asset_path_from_entry(
            &encrypted_runtime_apk_path,
        )
        .ok_or_else(|| {
            ApkRewriteError::Validation(format!(
                "encrypted runtime entry has unexpected path shape: {encrypted_runtime_apk_path}"
            ))
        })?;
        let patched_runtime_dex = patched_bootstrap_runtime_dex(runtime_dex_path, &runtime_class)?;
        let encrypted_runtime_dex = crypt_bootstrap_runtime_dex(
            &patched_runtime_dex,
            &rewrite_options.build_id,
            &encrypted_runtime_asset_path,
            &runtime_class,
        );
        write_bytes_entry(
            &mut output_archive,
            &encrypted_runtime_apk_path,
            &encrypted_runtime_dex,
            CompressionMethod::Deflated,
        )?;
        inserted_runtime_dex_entry = Some(InsertedPayloadEntry {
            apk_path: encrypted_runtime_apk_path.clone(),
            payload_path: BOOTSTRAP_RUNTIME_DEX_FILE.to_string(),
            sha256: sha256_bytes(&encrypted_runtime_dex),
        });
        inserted_runtime_dex_path = Some(encrypted_runtime_apk_path);
    }

    let mut inserted_native_library_entries = Vec::new();
    let mut inserted_native_library_paths = Vec::new();
    for (abi, library_path) in &payload_files.abi_libraries {
        let entry_name = native_library_entry_for_abi(abi, &native_library_name);
        reject_entry_collision(&seen_entries, &entry_name)?;
        inventory_entries.insert(entry_name.clone());
        let patched_native_library =
            patched_native_library(library_path, &runtime_class, &rewrite_options.build_id)?;
        write_bytes_entry(
            &mut output_archive,
            &entry_name,
            &patched_native_library,
            CompressionMethod::Stored,
        )?;
        inserted_native_library_entries.push(InsertedPayloadEntry {
            apk_path: entry_name.clone(),
            payload_path: format!("{abi}/{PAYLOAD_SECURITY_LIBRARY_NAME}"),
            sha256: sha256_bytes(&patched_native_library),
        });
        inserted_native_library_paths.push(entry_name);
    }

    reject_entry_collision(&seen_entries, &integrity_manifest_entry)?;
    inventory_entries.insert(integrity_manifest_entry.clone());
    let integrity_manifest = build_integrity_manifest(
        rewrite_options,
        package_name,
        InsertedPayloadEntries {
            provider: &inserted_manifest_provider,
            native_library_name: &native_library_name,
            dex_entry: &inserted_dex_entry,
            runtime_dex_entry: inserted_runtime_dex_entry.as_ref(),
            runtime_class: inserted_runtime_dex_entry
                .as_ref()
                .map(|_| runtime_class.as_str()),
            native_library_entries: &inserted_native_library_entries,
        },
        observed_protected_assets,
        apk_inventory_from_entries(&inventory_entries),
    )?;
    write_json_entry(
        &mut output_archive,
        &integrity_manifest_entry,
        &integrity_manifest,
    )?;

    output_archive.finish()?;
    fs::rename(&temporary_output, output)?;

    Ok(UnsignedApkRewriteReport {
        output_path: output.to_path_buf(),
        copied_entries,
        skipped_signature_entries,
        inserted_manifest_provider,
        inserted_integrity_manifest_entry: integrity_manifest_entry,
        inserted_dex_entry: inserted_dex_apk_path,
        inserted_runtime_dex_entry: inserted_runtime_dex_path,
        inserted_native_library_entries: inserted_native_library_paths,
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
    if let Some(runtime_dex_path) = &payload_files.bootstrap_runtime_dex_path {
        if !runtime_dex_path.is_file() {
            return Err(ApkRewriteError::Validation(format!(
                "bootstrap runtime DEX does not exist: {}",
                runtime_dex_path.display()
            )));
        }
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
    if !is_hex_sha256(&options.build_id) {
        return Err(ApkRewriteError::Validation(
            "build ID must be a 64-character SHA-256 hex digest".to_string(),
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
    inserted: InsertedPayloadEntries<'_>,
    observed_protected_assets: BTreeMap<String, ProtectedAssetObservation>,
    apk_inventory: IntegrityApkInventory,
) -> Result<IntegrityManifest, ApkRewriteError> {
    let input = &rewrite_options.integrity_manifest;
    require_payload_digest(input, &inserted.dex_entry.payload_path)?;
    let mut payload_file_sha256 = input.payload_file_sha256.clone();
    payload_file_sha256.insert(
        inserted.dex_entry.payload_path.clone(),
        inserted.dex_entry.sha256.clone(),
    );
    let mut protected_assets = Vec::new();
    protected_assets.push(IntegrityProtectedAsset {
        path: inserted.dex_entry.apk_path.clone(),
        sha256: inserted.dex_entry.sha256.clone(),
        kind: IntegrityProtectedAssetKind::BootstrapDex,
    });
    let encrypted_runtime = if let Some(runtime_entry) = inserted.runtime_dex_entry {
        require_payload_digest(input, &runtime_entry.payload_path)?;
        let runtime_class = inserted.runtime_class.ok_or_else(|| {
            ApkRewriteError::Validation("inserted runtime DEX is missing runtime class".to_string())
        })?;
        let asset_path = integrity_manifest_asset_path_from_entry(&runtime_entry.apk_path)
            .ok_or_else(|| {
                ApkRewriteError::Validation(format!(
                    "encrypted runtime path has unexpected shape: {}",
                    runtime_entry.apk_path
                ))
            })?;
        payload_file_sha256.insert(
            runtime_entry.payload_path.clone(),
            runtime_entry.sha256.clone(),
        );
        protected_assets.push(IntegrityProtectedAsset {
            path: runtime_entry.apk_path.clone(),
            sha256: runtime_entry.sha256.clone(),
            kind: IntegrityProtectedAssetKind::BootstrapRuntimeDex,
        });
        Some(IntegrityEncryptedRuntime {
            asset_path,
            class_name: runtime_class.to_string(),
            sha256: runtime_entry.sha256.clone(),
            encryption: BOOTSTRAP_RUNTIME_ENCRYPTION.to_string(),
        })
    } else {
        None
    };

    for entry_name in inserted.native_library_entries {
        require_payload_digest(input, &entry_name.payload_path)?;
        payload_file_sha256.insert(entry_name.payload_path.clone(), entry_name.sha256.clone());
        let _abi =
            native_library_abi_from_entry(&entry_name.apk_path, inserted.native_library_name)
                .ok_or_else(|| {
                    ApkRewriteError::Validation(format!(
                        "inserted native library path has unexpected shape: {}",
                        entry_name.apk_path
                    ))
                })?;
        protected_assets.push(IntegrityProtectedAsset {
            path: entry_name.apk_path.clone(),
            sha256: entry_name.sha256.clone(),
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
            name: inserted.provider.name.clone(),
            authorities: inserted.provider.authorities.clone(),
            exported: false,
            init_order: Some(rewrite_options.provider_init_order),
        },
        payload: IntegrityPayload {
            version: input.payload_version.clone(),
            native_library_name: inserted.native_library_name.to_string(),
            encrypted_runtime,
            files: payload_file_sha256,
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

fn require_payload_digest(
    input: &IntegrityManifestInput,
    path: &str,
) -> Result<(), ApkRewriteError> {
    input.payload_file_sha256.get(path).ok_or_else(|| {
        ApkRewriteError::Validation(format!(
            "payload manifest is missing digest for protected payload file {path}"
        ))
    })?;
    Ok(())
}

fn native_library_entry_for_abi(abi: &str, native_library_name: &str) -> String {
    format!("lib/{abi}/lib{native_library_name}.so")
}

fn native_library_abi_from_entry<'a>(
    entry_name: &'a str,
    native_library_name: &str,
) -> Option<&'a str> {
    let suffix = format!("/lib{native_library_name}.so");
    entry_name
        .strip_prefix("lib/")
        .and_then(|value| value.strip_suffix(&suffix))
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

fn patched_bootstrap_dex(
    path: &Path,
    provider_class: &str,
    build_id: &str,
) -> Result<Vec<u8>, ApkRewriteError> {
    let bytes = fs::read(path)?;
    let mut output = android_dex::patch_bootstrap_provider_class(&bytes, provider_class)
        .map_err(ApkRewriteError::Validation)?;
    patch_bootstrap_loader_strings(&mut output, build_id)?;
    android_dex::refresh_dex_header_hashes(&mut output);
    Ok(output)
}

fn patch_bootstrap_loader_strings(bytes: &mut [u8], build_id: &str) -> Result<(), ApkRewriteError> {
    let loader_xor_key = bootstrap_loader_xor_key_for_build_id(build_id)?;
    let mut replacements = 0usize;
    let mut missing = Vec::new();

    for loader_string in BOOTSTRAP_LOADER_BUILD_KEY_STRINGS {
        let source_encoded =
            encode_dex_int_array_string(loader_string.as_bytes(), BOOTSTRAP_LOADER_SOURCE_XOR_KEY);
        let build_encoded = encode_dex_int_array_string(loader_string.as_bytes(), loader_xor_key);
        let replacement_count = replace_all_bytes(bytes, &source_encoded, &build_encoded);
        if replacement_count == 0 {
            missing.push(*loader_string);
        }
        replacements += replacement_count;
    }

    if replacements == 0 {
        return Ok(());
    }
    if !missing.is_empty() {
        return Err(ApkRewriteError::Validation(format!(
            "bootstrap loader DEX is missing expected encoded build-key string marker(s): {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn bootstrap_loader_xor_key_for_build_id(build_id: &str) -> Result<u8, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(format!(
            "build ID must be a 64-character SHA-256 hex digest: {build_id}"
        )));
    }
    let source_key = BOOTSTRAP_LOADER_SOURCE_XOR_KEY;
    let mut key = u8::from_str_radix(&build_id[4..6], 16).map_err(|error| {
        ApkRewriteError::Validation(format!("invalid build ID hex loader byte: {error}"))
    })? ^ 0x9e;
    for tweak in [0x73, 0xb5, 0x2d, 0xe1] {
        if key != 0 && key != source_key {
            return Ok(key);
        }
        key ^= tweak;
    }
    if key == 0 || key == source_key {
        key = source_key ^ 0xa5;
    }
    Ok(key)
}

fn encode_dex_int_array_string(bytes: &[u8], key: u8) -> Vec<u8> {
    encode_native_string(bytes, key)
        .into_iter()
        .flat_map(|byte| u32::from(byte).to_le_bytes())
        .collect()
}

fn patched_bootstrap_runtime_dex(
    path: &Path,
    runtime_class: &str,
) -> Result<Vec<u8>, ApkRewriteError> {
    let bytes = fs::read(path)?;
    android_dex::patch_bootstrap_runtime_class(&bytes, runtime_class)
        .map_err(ApkRewriteError::Validation)
}

fn crypt_bootstrap_runtime_dex(
    bytes: &[u8],
    build_id: &str,
    asset_path: &str,
    runtime_class: &str,
) -> Vec<u8> {
    let normalized_build_id = build_id.to_ascii_lowercase();
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(BOOTSTRAP_RUNTIME_KEY_DOMAIN.as_bytes());
    seed_hasher.update([0]);
    seed_hasher.update(normalized_build_id.as_bytes());
    seed_hasher.update([0]);
    seed_hasher.update(asset_path.as_bytes());
    seed_hasher.update([0]);
    seed_hasher.update(runtime_class.as_bytes());
    let seed = seed_hasher.finalize();

    let mut output = Vec::with_capacity(bytes.len());
    for (counter, chunk) in bytes.chunks(32).enumerate() {
        let mut block_hasher = Sha256::new();
        block_hasher.update(seed.as_slice());
        block_hasher.update((counter as u32).to_be_bytes());
        let block = block_hasher.finalize();
        for (byte, key_byte) in chunk.iter().zip(block.iter()) {
            output.push(*byte ^ *key_byte);
        }
    }
    output
}

fn patched_native_library(
    path: &Path,
    runtime_class: &str,
    build_id: &str,
) -> Result<Vec<u8>, ApkRewriteError> {
    let bytes = fs::read(path)?;
    patch_native_bootstrap_strings(&bytes, runtime_class, build_id)
}

fn patch_native_bootstrap_strings(
    bytes: &[u8],
    runtime_class: &str,
    build_id: &str,
) -> Result<Vec<u8>, ApkRewriteError> {
    let bootstrap_xor_key = native_bootstrap_xor_key_for_build_id(build_id)?;
    let detector_xor_key = native_detector_xor_key_for_build_id(build_id)?;
    let original = android_dex::BOOTSTRAP_RUNTIME_CLASS.replace('.', "/");
    let replacement = runtime_class.replace('.', "/");
    if original.len() != replacement.len() {
        return Err(ApkRewriteError::Validation(format!(
            "replacement bootstrap runtime class must be {} bytes after slash conversion",
            original.len()
        )));
    }
    let mut output = bytes.to_vec();
    patch_native_xor_key_marker(
        &mut output,
        NATIVE_BOOTSTRAP_XOR_KEY_MARKER,
        bootstrap_xor_key,
        "bootstrap string",
    )?;
    patch_native_xor_key_marker(
        &mut output,
        NATIVE_DETECTOR_XOR_KEY_MARKER,
        detector_xor_key,
        "detector string",
    )?;
    patch_native_encoded_string(
        &mut output,
        original.as_bytes(),
        replacement.as_bytes(),
        bootstrap_xor_key,
        "bootstrap runtime class",
    )?;
    for method_name in NATIVE_BOOTSTRAP_METHOD_NAMES {
        patch_native_encoded_string(
            &mut output,
            method_name.as_bytes(),
            method_name.as_bytes(),
            bootstrap_xor_key,
            method_name,
        )?;
    }
    patch_native_detector_strings(&mut output, detector_xor_key)?;
    Ok(output)
}

fn native_bootstrap_xor_key_for_build_id(build_id: &str) -> Result<u8, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(format!(
            "build ID must be a 64-character SHA-256 hex digest: {build_id}"
        )));
    }
    let mut key = u8::from_str_radix(&build_id[..2], 16).map_err(|error| {
        ApkRewriteError::Validation(format!("invalid build ID hex prefix: {error}"))
    })? ^ 0xa7;
    if key == 0 || key == NATIVE_SOURCE_XOR_KEY {
        key ^= 0x3d;
    }
    Ok(key)
}

fn native_detector_xor_key_for_build_id(build_id: &str) -> Result<u8, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(format!(
            "build ID must be a 64-character SHA-256 hex digest: {build_id}"
        )));
    }
    let bootstrap_xor_key = native_bootstrap_xor_key_for_build_id(build_id)?;
    let mut key = u8::from_str_radix(&build_id[2..4], 16).map_err(|error| {
        ApkRewriteError::Validation(format!("invalid build ID hex detector byte: {error}"))
    })? ^ 0xc3;
    for tweak in [0x5d, 0xa6, 0x39, 0xe7] {
        if key != 0 && key != NATIVE_SOURCE_XOR_KEY && key != bootstrap_xor_key {
            return Ok(key);
        }
        key ^= tweak;
    }
    for offset in 1u16..=u8::MAX as u16 {
        let candidate = key.wrapping_add(offset as u8);
        if candidate != 0 && candidate != NATIVE_SOURCE_XOR_KEY && candidate != bootstrap_xor_key {
            return Ok(candidate);
        }
    }
    Err(ApkRewriteError::Validation(
        "could not derive native detector XOR key".to_string(),
    ))
}

fn patch_native_xor_key_marker(
    bytes: &mut [u8],
    marker: &[u8],
    xor_key: u8,
    label: &str,
) -> Result<(), ApkRewriteError> {
    let mut replacement = marker.to_vec();
    replacement[NATIVE_BOOTSTRAP_XOR_KEY_INDEX] = xor_key;
    let replacements = replace_all_bytes(bytes, marker, &replacement);
    if replacements != 1 {
        return Err(ApkRewriteError::Validation(format!(
            "native payload library must contain exactly one {label} key marker, found {replacements}"
        )));
    }
    Ok(())
}

fn patch_native_detector_strings(
    bytes: &mut [u8],
    detector_xor_key: u8,
) -> Result<(), ApkRewriteError> {
    let mut strings = NATIVE_DETECTOR_STRINGS.to_vec();
    strings.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));

    let mut replacements = 0usize;
    for detector_string in strings {
        replacements += patch_native_encoded_string_optional(
            bytes,
            detector_string.as_bytes(),
            detector_string.as_bytes(),
            detector_xor_key,
        );
    }
    if replacements == 0 {
        return Err(ApkRewriteError::Validation(
            "native payload library does not contain expected encoded detector strings".to_string(),
        ));
    }
    Ok(())
}

fn patch_native_encoded_string(
    bytes: &mut [u8],
    original_plaintext: &[u8],
    replacement_plaintext: &[u8],
    bootstrap_xor_key: u8,
    label: &str,
) -> Result<(), ApkRewriteError> {
    let replacements = patch_native_encoded_string_optional(
        bytes,
        original_plaintext,
        replacement_plaintext,
        bootstrap_xor_key,
    );
    if replacements == 0 {
        return Err(ApkRewriteError::Validation(format!(
            "native payload library does not contain expected encoded {label}"
        )));
    }
    Ok(())
}

fn patch_native_encoded_string_optional(
    bytes: &mut [u8],
    original_plaintext: &[u8],
    replacement_plaintext: &[u8],
    xor_key: u8,
) -> usize {
    let original_encoded = encode_native_string(original_plaintext, NATIVE_SOURCE_XOR_KEY);
    let replacement_encoded = encode_native_string(replacement_plaintext, xor_key);
    replace_all_bytes(bytes, &original_encoded, &replacement_encoded)
}

fn encode_native_string(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ native_string_mask(key, index, bytes.len()))
        .collect()
}

fn native_string_mask(key: u8, index: usize, length: usize) -> u8 {
    let position = (index as u8).wrapping_add(1);
    let span = length as u8;
    let mix = 0x9d_u8
        .wrapping_add(position.wrapping_mul(0x3d))
        .wrapping_add(span.wrapping_mul(0x11));
    key ^ mix ^ position.rotate_left(3)
}

fn replace_all_bytes(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) -> usize {
    if needle.is_empty() || needle.len() != replacement.len() || bytes.len() < needle.len() {
        return 0;
    }

    let mut count = 0usize;
    let mut index = 0usize;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            bytes[index..index + replacement.len()].copy_from_slice(replacement);
            count += 1;
            index += needle.len();
        } else {
            index += 1;
        }
    }
    count
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
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

fn write_bytes_entry(
    output_archive: &mut ZipWriter<File>,
    entry_name: &str,
    bytes: &[u8],
    compression_method: CompressionMethod,
) -> Result<(), ApkRewriteError> {
    let options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .unix_permissions(0o644);
    output_archive.start_file(entry_name, options)?;
    output_archive.write_all(bytes)?;
    Ok(())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn bootstrap_manifest_asset_metadata_name_for_build_id(
    build_id: &str,
) -> Result<String, ApkRewriteError> {
    if !is_hex_sha256(build_id) {
        return Err(ApkRewriteError::Validation(
            "build ID must be a 64-character SHA-256 hex digest".to_string(),
        ));
    }
    Ok(format!("r{}", build_id[..12].to_ascii_lowercase()))
}

fn integrity_manifest_asset_path_from_entry(entry: &str) -> Option<String> {
    entry
        .strip_prefix("assets/")
        .filter(|value| is_safe_asset_path(value))
        .map(ToString::to_string)
}

fn is_safe_asset_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
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
        default_runtime_detections, encrypted_runtime_entry_for_build_id, hex_lower,
        integrity_manifest_entry_for_build_id, is_jar_signature_metadata_entry, is_zip_slip_path,
        native_library_name_for_build_id, rewrite_unsigned_apk_with_payload, ApkRewriteOptions,
        IntegrityManifest, IntegrityManifestInput, IntegrityProtectedAssetKind,
        IntegrityRiskAction, IntegrityRiskThresholds, IntegrityRuntimeMonitoring,
        IntegrityRuntimePolicy, IntegrityTool, PayloadFiles,
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
        let runtime_dex_path = root.join("bootstrap-runtime.dex");
        let native_library_path = root.join("libsecurity.so");
        fs::write(&bootstrap_dex_path, bootstrap_dex_bytes()).expect("write bootstrap dex");
        fs::write(&runtime_dex_path, runtime_dex_bytes()).expect("write runtime dex");
        fs::write(&native_library_path, native_library_bytes()).expect("write native library");

        let payload = PayloadFiles {
            bootstrap_dex_path,
            bootstrap_runtime_dex_path: Some(runtime_dex_path),
            abi_libraries: BTreeMap::from([("arm64-v8a".to_string(), native_library_path)]),
        };
        let rewrite_options = rewrite_options();
        let expected_authorities =
            bootstrap_provider_authority("com.example.mobile", &rewrite_options.build_id);
        let expected_provider_class =
            android_dex::bootstrap_provider_class_for_build_id(&rewrite_options.build_id)
                .expect("provider class");
        let expected_runtime_class =
            android_dex::bootstrap_runtime_class_for_build_id(&rewrite_options.build_id)
                .expect("runtime class");
        let expected_integrity_manifest_entry =
            integrity_manifest_entry_for_build_id(&rewrite_options.build_id)
                .expect("integrity manifest entry");
        let expected_integrity_manifest_asset = expected_integrity_manifest_entry
            .strip_prefix("assets/")
            .expect("asset path");
        let expected_native_library_name =
            native_library_name_for_build_id(&rewrite_options.build_id).expect("library name");
        let expected_native_library_entry =
            format!("lib/arm64-v8a/lib{expected_native_library_name}.so");
        let expected_bootstrap_dex = patched_bootstrap_dex_bytes(&rewrite_options.build_id);
        let expected_runtime_dex = patched_bootstrap_runtime_dex_bytes(&rewrite_options.build_id);
        let expected_encrypted_runtime_entry =
            encrypted_runtime_entry_for_build_id(&rewrite_options.build_id).expect("runtime entry");
        let expected_encrypted_runtime_asset = expected_encrypted_runtime_entry
            .strip_prefix("assets/")
            .expect("runtime asset path");
        let expected_encrypted_runtime_dex = super::crypt_bootstrap_runtime_dex(
            &expected_runtime_dex,
            &rewrite_options.build_id,
            expected_encrypted_runtime_asset,
            &expected_runtime_class,
        );
        let expected_native_library = patched_native_library_bytes(&rewrite_options.build_id);

        let report =
            rewrite_unsigned_apk_with_payload(&input_apk, &output_apk, &payload, &rewrite_options)
                .expect("rewrite");

        assert_eq!(report.inserted_dex_entry, "classes3.dex");
        assert_eq!(
            report.inserted_runtime_dex_entry,
            Some(expected_encrypted_runtime_entry.clone())
        );
        assert_eq!(
            report.inserted_manifest_provider.name,
            expected_provider_class.clone()
        );
        assert_eq!(
            report.inserted_manifest_provider.authorities,
            expected_authorities
        );
        assert_eq!(
            report.inserted_native_library_entries,
            vec![expected_native_library_entry.clone()]
        );
        assert_eq!(
            report.inserted_integrity_manifest_entry,
            expected_integrity_manifest_entry.clone()
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
        assert_eq!(
            read_zip_entry(&mut archive, "classes3.dex"),
            expected_bootstrap_dex
        );
        assert_bootstrap_loader_strings_use_build_key(
            &read_zip_entry(&mut archive, "classes3.dex"),
            &rewrite_options.build_id,
        );
        let manifest = parse_manifest(&read_zip_entry(&mut archive, "AndroidManifest.xml"))
            .expect("parse output manifest");
        assert!(manifest.providers.iter().any(|provider| {
            provider.name.as_deref() == Some(expected_provider_class.as_str())
                && provider.authorities.as_deref() == Some(expected_authorities.as_str())
                && provider.exported == Some(false)
                && provider
                    .meta_data
                    .iter()
                    .any(|entry| entry.value.as_deref() == Some(expected_integrity_manifest_asset))
        }));
        let native_entry_bytes = read_zip_entry(&mut archive, &expected_native_library_entry);
        assert_eq!(native_entry_bytes, expected_native_library);
        assert_native_strings_use_build_keys(
            &native_entry_bytes,
            &expected_runtime_class,
            &rewrite_options.build_id,
        );
        assert_eq!(
            archive
                .by_name(&expected_native_library_entry)
                .expect("native entry")
                .compression(),
            CompressionMethod::Stored
        );
        assert!(archive.by_name("assets/index.android.bundle").is_ok());
        let encrypted_runtime_entry_bytes =
            read_zip_entry(&mut archive, &expected_encrypted_runtime_entry);
        assert_eq!(
            encrypted_runtime_entry_bytes,
            expected_encrypted_runtime_dex
        );
        assert!(!contains_bytes(
            &encrypted_runtime_entry_bytes,
            android_dex::BOOTSTRAP_RUNTIME_CLASS
                .replace('.', "/")
                .as_bytes()
        ));
        assert!(!contains_bytes(
            &encrypted_runtime_entry_bytes,
            expected_runtime_class.replace('.', "/").as_bytes()
        ));
        let decrypted_runtime_dex = super::crypt_bootstrap_runtime_dex(
            &encrypted_runtime_entry_bytes,
            &rewrite_options.build_id,
            expected_encrypted_runtime_asset,
            &expected_runtime_class,
        );
        assert_eq!(decrypted_runtime_dex, expected_runtime_dex);
        let integrity_manifest: IntegrityManifest = serde_json::from_slice(&read_zip_entry(
            &mut archive,
            &expected_integrity_manifest_entry,
        ))
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
            sha256_bytes(&expected_bootstrap_dex)
        );
        assert_eq!(
            integrity_manifest.payload.files["bootstrap-runtime.dex"],
            sha256_bytes(&expected_encrypted_runtime_dex)
        );
        assert_eq!(
            integrity_manifest.payload.files["arm64-v8a/libsecurity.so"],
            sha256_bytes(&expected_native_library)
        );
        assert_eq!(
            integrity_manifest.payload.native_library_name,
            expected_native_library_name
        );
        let encrypted_runtime = integrity_manifest
            .payload
            .encrypted_runtime
            .as_ref()
            .expect("encrypted runtime metadata");
        assert_eq!(
            encrypted_runtime.asset_path,
            expected_encrypted_runtime_asset
        );
        assert_eq!(encrypted_runtime.class_name, expected_runtime_class);
        assert_eq!(
            encrypted_runtime.sha256,
            sha256_bytes(&expected_encrypted_runtime_dex)
        );
        assert_eq!(
            encrypted_runtime.encryption,
            super::BOOTSTRAP_RUNTIME_ENCRYPTION
        );
        assert_eq!(integrity_manifest.policy.runtime.thresholds.report, 20);
        assert_eq!(integrity_manifest.policy.runtime.startup_budget_ms, 50);
        assert_eq!(integrity_manifest.apk_inventory.entry_count, 10);
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
                && asset.sha256 == sha256_bytes(&expected_bootstrap_dex)
                && asset.kind == IntegrityProtectedAssetKind::BootstrapDex
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == expected_encrypted_runtime_entry
                && asset.sha256 == sha256_bytes(&expected_encrypted_runtime_dex)
                && asset.kind == IntegrityProtectedAssetKind::BootstrapRuntimeDex
        }));
        assert!(integrity_manifest.protected_assets.iter().any(|asset| {
            asset.path == expected_native_library_entry
                && asset.sha256 == sha256_bytes(&expected_native_library)
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
                ("lib/arm64-v8a/librsa91f30c2d41e.so", b"existing".to_vec()),
            ],
        );

        let bootstrap_dex_path = root.join("bootstrap.dex");
        let native_library_path = root.join("libsecurity.so");
        fs::write(&bootstrap_dex_path, bootstrap_dex_bytes()).expect("write bootstrap dex");
        fs::write(&native_library_path, native_library_bytes()).expect("write native library");

        let payload = PayloadFiles {
            bootstrap_dex_path,
            bootstrap_runtime_dex_path: None,
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
                    ("bootstrap-runtime.dex".to_string(), "3".repeat(64)),
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

    fn bootstrap_dex_bytes() -> Vec<u8> {
        let original = android_dex::BOOTSTRAP_PROVIDER_CLASS.replace('.', "/");
        let mut bytes = format!("payload L{}; L{}$RuntimePolicy;", original, original).into_bytes();
        for loader_string in super::BOOTSTRAP_LOADER_BUILD_KEY_STRINGS {
            bytes.extend(super::encode_dex_int_array_string(
                loader_string.as_bytes(),
                super::BOOTSTRAP_LOADER_SOURCE_XOR_KEY,
            ));
        }
        bytes
    }

    fn runtime_dex_bytes() -> Vec<u8> {
        let original = android_dex::BOOTSTRAP_RUNTIME_CLASS.replace('.', "/");
        format!("payload L{}; L{}$RuntimePolicy;", original, original).into_bytes()
    }

    fn native_library_bytes() -> Vec<u8> {
        let original = android_dex::BOOTSTRAP_RUNTIME_CLASS.replace('.', "/");
        let mut bytes = b"\x7fELF payload ".to_vec();
        bytes.extend_from_slice(super::NATIVE_BOOTSTRAP_XOR_KEY_MARKER);
        bytes.extend_from_slice(super::NATIVE_DETECTOR_XOR_KEY_MARKER);
        bytes.extend_from_slice(&super::encode_native_string(
            original.as_bytes(),
            super::NATIVE_SOURCE_XOR_KEY,
        ));
        for method_name in super::NATIVE_BOOTSTRAP_METHOD_NAMES {
            bytes.extend_from_slice(&super::encode_native_string(
                method_name.as_bytes(),
                super::NATIVE_SOURCE_XOR_KEY,
            ));
        }
        for detector_string in super::NATIVE_DETECTOR_STRINGS {
            bytes.extend_from_slice(&super::encode_native_string(
                detector_string.as_bytes(),
                super::NATIVE_SOURCE_XOR_KEY,
            ));
        }
        bytes
    }

    fn patched_bootstrap_dex_bytes(build_id: &str) -> Vec<u8> {
        let provider_class =
            android_dex::bootstrap_provider_class_for_build_id(build_id).expect("provider class");
        let mut bytes =
            android_dex::patch_bootstrap_provider_class(&bootstrap_dex_bytes(), &provider_class)
                .expect("patched bootstrap dex");
        super::patch_bootstrap_loader_strings(&mut bytes, build_id)
            .expect("patched bootstrap loader strings");
        bytes
    }

    fn patched_bootstrap_runtime_dex_bytes(build_id: &str) -> Vec<u8> {
        let runtime_class =
            android_dex::bootstrap_runtime_class_for_build_id(build_id).expect("runtime class");
        android_dex::patch_bootstrap_runtime_class(&runtime_dex_bytes(), &runtime_class)
            .expect("patched runtime dex")
    }

    fn patched_native_library_bytes(build_id: &str) -> Vec<u8> {
        let runtime_class =
            android_dex::bootstrap_runtime_class_for_build_id(build_id).expect("runtime class");
        super::patch_native_bootstrap_strings(&native_library_bytes(), &runtime_class, build_id)
            .expect("patched native library")
    }

    fn assert_native_strings_use_build_keys(bytes: &[u8], runtime_class: &str, build_id: &str) {
        let bootstrap_xor_key =
            super::native_bootstrap_xor_key_for_build_id(build_id).expect("bootstrap key");
        let detector_xor_key =
            super::native_detector_xor_key_for_build_id(build_id).expect("detector key");
        let original = android_dex::BOOTSTRAP_RUNTIME_CLASS.replace('.', "/");
        let replacement = runtime_class.replace('.', "/");
        let original_encoded =
            super::encode_native_string(original.as_bytes(), super::NATIVE_SOURCE_XOR_KEY);
        let replacement_encoded =
            super::encode_native_string(replacement.as_bytes(), bootstrap_xor_key);
        let mut patched_key_marker = super::NATIVE_BOOTSTRAP_XOR_KEY_MARKER.to_vec();
        patched_key_marker[super::NATIVE_BOOTSTRAP_XOR_KEY_INDEX] = bootstrap_xor_key;
        let mut patched_detector_key_marker = super::NATIVE_DETECTOR_XOR_KEY_MARKER.to_vec();
        patched_detector_key_marker[super::NATIVE_BOOTSTRAP_XOR_KEY_INDEX] = detector_xor_key;

        assert!(!contains_bytes(
            bytes,
            super::NATIVE_BOOTSTRAP_XOR_KEY_MARKER
        ));
        assert!(contains_bytes(bytes, &patched_key_marker));
        assert!(!contains_bytes(
            bytes,
            super::NATIVE_DETECTOR_XOR_KEY_MARKER
        ));
        assert!(contains_bytes(bytes, &patched_detector_key_marker));
        assert!(!contains_bytes(bytes, &original_encoded));
        assert!(contains_bytes(bytes, &replacement_encoded));
        for method_name in super::NATIVE_BOOTSTRAP_METHOD_NAMES {
            let fixed_key_encoded =
                super::encode_native_string(method_name.as_bytes(), super::NATIVE_SOURCE_XOR_KEY);
            let build_key_encoded =
                super::encode_native_string(method_name.as_bytes(), bootstrap_xor_key);
            assert!(!contains_bytes(bytes, &fixed_key_encoded));
            assert!(contains_bytes(bytes, &build_key_encoded));
        }
        for detector_string in super::NATIVE_DETECTOR_STRINGS {
            let fixed_key_encoded = super::encode_native_string(
                detector_string.as_bytes(),
                super::NATIVE_SOURCE_XOR_KEY,
            );
            let build_key_encoded =
                super::encode_native_string(detector_string.as_bytes(), detector_xor_key);
            assert!(!contains_bytes(bytes, &fixed_key_encoded));
            assert!(contains_bytes(bytes, &build_key_encoded));
        }
    }

    fn assert_bootstrap_loader_strings_use_build_key(bytes: &[u8], build_id: &str) {
        let loader_xor_key =
            super::bootstrap_loader_xor_key_for_build_id(build_id).expect("loader key");
        for loader_string in super::BOOTSTRAP_LOADER_BUILD_KEY_STRINGS {
            let fixed_key_encoded = super::encode_dex_int_array_string(
                loader_string.as_bytes(),
                super::BOOTSTRAP_LOADER_SOURCE_XOR_KEY,
            );
            let build_key_encoded =
                super::encode_dex_int_array_string(loader_string.as_bytes(), loader_xor_key);
            assert!(!contains_bytes(bytes, &fixed_key_encoded));
            assert!(contains_bytes(bytes, &build_key_encoded));
        }
    }

    fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
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
