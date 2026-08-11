use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use android_apk::is_zip_slip_path;
use android_axml::parse_manifest;
use rasp_core::ExitCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const INSPECTION_SCHEMA_VERSION: u32 = 1;
const MAX_APK_ENTRIES: usize = 200_000;
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_APK_SIGNING_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_V1_SIGNATURE_BLOCK_BYTES: u64 = 16 * 1024 * 1024;
const ANDROID_MANIFEST_PATH: &str = "AndroidManifest.xml";
const APK_SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const APK_SIG_SCHEME_V2_BLOCK_ID: u32 = 0x7109_871a;
const APK_SIG_SCHEME_V3_BLOCK_ID: u32 = 0xf053_68c0;
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("failed to access artifact: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported artifact: {0}")]
    UnsupportedArtifact(String),
    #[error("artifact inspection failed: {0}")]
    Inspection(String),
    #[error("invalid APK ZIP structure: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("unsafe APK ZIP structure: {0}")]
    UnsafeZip(String),
}

impl InspectError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            InspectError::UnsupportedArtifact(_) => ExitCode::UnsupportedArtifact,
            InspectError::Io(_)
            | InspectError::Inspection(_)
            | InspectError::Zip(_)
            | InspectError::UnsafeZip(_) => ExitCode::ArtifactInspectionFailure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactType {
    Apk,
    Aab,
    Ipa,
    Xcarchive,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectionResult {
    pub schema_version: u32,
    pub artifact_type: ArtifactType,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub package_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<u32>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub supported_abis: Vec<String>,
    pub dex_files: Vec<DexFile>,
    pub native_libraries: Vec<NativeLibrary>,
    pub flutter: Option<FlutterInfo>,
    pub react_native_engine: Option<ReactNativeEngine>,
    pub javascript_bundle_path: Option<String>,
    pub application_class: Option<String>,
    pub extract_native_libs: Option<bool>,
    pub main_activity: Option<String>,
    pub content_providers: Vec<ContentProvider>,
    pub detected_signature_schemes: Vec<ApkSignatureScheme>,
    pub signature_certificates: Vec<SignatureCertificate>,
    pub signature_entries: Vec<String>,
    pub apk_compression: ApkCompressionInfo,
    pub existing_security_products: Vec<String>,
    pub compatibility_warnings: Vec<String>,
    pub warnings: Vec<String>,
}

impl InspectionResult {
    pub fn unsupported(path: PathBuf) -> Self {
        Self {
            schema_version: INSPECTION_SCHEMA_VERSION,
            artifact_type: ArtifactType::Unknown,
            path,
            size_bytes: 0,
            sha256: String::new(),
            package_name: None,
            version_name: None,
            version_code: None,
            min_sdk: None,
            target_sdk: None,
            supported_abis: Vec::new(),
            dex_files: Vec::new(),
            native_libraries: Vec::new(),
            flutter: None,
            react_native_engine: None,
            javascript_bundle_path: None,
            application_class: None,
            extract_native_libs: None,
            main_activity: None,
            content_providers: Vec::new(),
            detected_signature_schemes: Vec::new(),
            signature_certificates: Vec::new(),
            signature_entries: Vec::new(),
            apk_compression: ApkCompressionInfo::default(),
            existing_security_products: Vec::new(),
            compatibility_warnings: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DexFile {
    pub path: String,
    pub size_bytes: u64,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeLibrary {
    pub path: String,
    pub abi: String,
    pub name: String,
    pub size_bytes: u64,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentProvider {
    pub name: Option<String>,
    pub authorities: Option<String>,
    pub exported: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApkSignatureScheme {
    V1Jar,
    V2,
    V3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureCertificate {
    pub sha256: String,
    pub schemes: Vec<ApkSignatureScheme>,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactNativeEngine {
    Hermes,
    JavaScriptCore,
    UnknownReactNative,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlutterInfo {
    pub detected: bool,
    pub app_libraries: Vec<String>,
    pub engine_libraries: Vec<String>,
    pub asset_entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApkCompressionInfo {
    pub total_entries: usize,
    pub compressed_entries: usize,
    pub stored_entries: usize,
    pub duplicate_paths: Vec<String>,
    pub zip_slip_paths: Vec<String>,
    pub total_uncompressed_bytes: u64,
}

pub fn inspect_apk(path: impl AsRef<Path>) -> Result<InspectionResult, InspectError> {
    let path = path.as_ref();
    validate_input_path(path)?;

    if detect_artifact_type(path) != ArtifactType::Apk {
        return Err(InspectError::UnsupportedArtifact(format!(
            "Release 1.0 supports APK input only: {}",
            path.display()
        )));
    }

    let metadata = fs::metadata(path)?;
    let sha256 = sha256_file(path)?;
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    if archive.len() > MAX_APK_ENTRIES {
        return Err(InspectError::UnsafeZip(format!(
            "entry count {} exceeds limit {MAX_APK_ENTRIES}",
            archive.len()
        )));
    }

    let mut seen_paths = BTreeSet::new();
    let mut duplicate_paths = BTreeSet::new();
    let mut zip_slip_paths = BTreeSet::new();
    let mut dex_files = Vec::new();
    let mut native_libraries = Vec::new();
    let mut signature_entries = Vec::new();
    let mut v1_signature_blocks = Vec::new();
    let mut manifest_bytes = None;
    let mut javascript_bundle_path = None;
    let mut flutter_asset_entries = Vec::new();
    let mut compression = ApkCompressionInfo::default();
    let mut entry_names = Vec::new();
    let mut warnings = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let path_name = entry.name().to_string();
        entry_names.push(path_name.clone());

        if !seen_paths.insert(path_name.clone()) {
            duplicate_paths.insert(path_name.clone());
        }
        if is_zip_slip_path(&path_name) {
            zip_slip_paths.insert(path_name.clone());
        }

        compression.total_entries += 1;
        compression.total_uncompressed_bytes = compression
            .total_uncompressed_bytes
            .saturating_add(entry.size());
        if compression.total_uncompressed_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(InspectError::UnsafeZip(format!(
                "total uncompressed size exceeds {} bytes",
                MAX_TOTAL_UNCOMPRESSED_BYTES
            )));
        }

        let compressed = entry.compression() != zip::CompressionMethod::Stored;
        if compressed {
            compression.compressed_entries += 1;
        } else {
            compression.stored_entries += 1;
        }

        if is_dex_path(&path_name) {
            dex_files.push(DexFile {
                path: path_name.clone(),
                size_bytes: entry.size(),
                compressed,
            });
        }

        if let Some(native_library) =
            native_library_from_entry(&path_name, entry.size(), compressed)
        {
            native_libraries.push(native_library);
        }

        if is_signature_entry(&path_name) {
            signature_entries.push(path_name.clone());
            if is_v1_certificate_signature_entry(&path_name) {
                if entry.size() > MAX_V1_SIGNATURE_BLOCK_BYTES {
                    warnings.push(format!(
                        "skipped v1 signature block {} because its size {} exceeds limit {}",
                        path_name,
                        entry.size(),
                        MAX_V1_SIGNATURE_BLOCK_BYTES
                    ));
                } else {
                    let mut bytes = Vec::with_capacity(entry.size() as usize);
                    entry.read_to_end(&mut bytes)?;
                    v1_signature_blocks.push((path_name.clone(), bytes));
                }
            }
        }

        if is_javascript_bundle_path(&path_name) && javascript_bundle_path.is_none() {
            javascript_bundle_path = Some(path_name.clone());
        }

        if is_flutter_asset_entry(&path_name) && !entry.is_dir() {
            flutter_asset_entries.push(path_name.clone());
        }

        if path_name == ANDROID_MANIFEST_PATH {
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut bytes)?;
            manifest_bytes = Some(bytes);
        }
    }

    compression.duplicate_paths = duplicate_paths.into_iter().collect();
    compression.zip_slip_paths = zip_slip_paths.into_iter().collect();

    if !compression.duplicate_paths.is_empty() {
        return Err(InspectError::UnsafeZip(format!(
            "duplicate ZIP paths found: {}",
            compression.duplicate_paths.join(", ")
        )));
    }
    if !compression.zip_slip_paths.is_empty() {
        return Err(InspectError::UnsafeZip(format!(
            "ZIP-slip paths found: {}",
            compression.zip_slip_paths.join(", ")
        )));
    }

    dex_files.sort_by_key(|dex_file| dex_order(&dex_file.path));
    native_libraries.sort_by(|left, right| left.path.cmp(&right.path));
    signature_entries.sort();
    entry_names.sort();

    let supported_abis = supported_abis(&native_libraries);
    let existing_security_products = detect_security_products(&entry_names);
    let flutter = detect_flutter(&native_libraries, &flutter_asset_entries);
    let react_native_engine = detect_react_native_engine(
        &entry_names,
        &native_libraries,
        javascript_bundle_path.as_deref(),
    );
    let signature_inspection = inspect_signatures(path, &signature_entries, &v1_signature_blocks)?;

    let mut compatibility_warnings = Vec::new();
    let mut package_name = None;
    let mut version_name = None;
    let mut version_code = None;
    let mut min_sdk = None;
    let mut target_sdk = None;
    let mut application_class = None;
    let mut extract_native_libs = None;
    let mut main_activity = None;
    let mut content_providers = Vec::new();

    match manifest_bytes {
        Some(bytes) => match parse_manifest(&bytes) {
            Ok(manifest) => {
                package_name = manifest.package_name;
                version_name = manifest.version_name;
                version_code = manifest.version_code;
                min_sdk = manifest.min_sdk;
                target_sdk = manifest.target_sdk;
                application_class = manifest.application_class;
                extract_native_libs = manifest.extract_native_libs;
                main_activity = manifest.main_activity;
                content_providers = manifest
                    .providers
                    .into_iter()
                    .map(|provider| ContentProvider {
                        name: provider.name,
                        authorities: provider.authorities,
                        exported: provider.exported,
                    })
                    .collect();
            }
            Err(error) => warnings.push(error.to_string()),
        },
        None => {
            return Err(InspectError::Inspection(
                "APK is missing AndroidManifest.xml".to_string(),
            ));
        }
    }

    if min_sdk.is_some_and(|value| value < 23) {
        compatibility_warnings
            .push("minSdkVersion is below the Release 1.0 minimum of 23".to_string());
    }
    if target_sdk.is_some_and(|value| !(33..=36).contains(&value)) {
        compatibility_warnings.push(
            "targetSdkVersion is outside the Release 1.0 compatibility range of 33-36".to_string(),
        );
    }
    if dex_files.is_empty() {
        compatibility_warnings.push("APK contains no classes*.dex entries".to_string());
    }
    if javascript_bundle_path.is_none() && flutter.is_none() {
        compatibility_warnings
            .push("React Native JavaScript bundle was not identified".to_string());
    }
    if supported_abis.is_empty() {
        compatibility_warnings.push("APK contains no native library ABI directories".to_string());
    }
    if !supported_abis.iter().any(|abi| abi == "arm64-v8a") {
        compatibility_warnings.push("APK does not contain arm64-v8a native libraries".to_string());
    }
    if package_name.is_none() {
        warnings.push("package name was not decoded from AndroidManifest.xml".to_string());
    }
    if main_activity.is_none() {
        warnings
            .push("launchable main activity was not decoded from AndroidManifest.xml".to_string());
    }
    warnings.extend(signature_inspection.warnings);

    Ok(InspectionResult {
        schema_version: INSPECTION_SCHEMA_VERSION,
        artifact_type: ArtifactType::Apk,
        path: path.to_path_buf(),
        size_bytes: metadata.len(),
        sha256,
        package_name,
        version_name,
        version_code,
        min_sdk,
        target_sdk,
        supported_abis,
        dex_files,
        native_libraries,
        flutter,
        react_native_engine,
        javascript_bundle_path,
        application_class,
        extract_native_libs,
        main_activity,
        content_providers,
        detected_signature_schemes: signature_inspection.detected_schemes,
        signature_certificates: signature_inspection.certificates,
        signature_entries,
        apk_compression: compression,
        existing_security_products,
        compatibility_warnings,
        warnings,
    })
}

fn validate_input_path(path: &Path) -> Result<(), InspectError> {
    let symlink_metadata = fs::symlink_metadata(path)?;
    if symlink_metadata.file_type().is_symlink() {
        return Err(InspectError::Inspection(format!(
            "input artifact must not be a symbolic link: {}",
            path.display()
        )));
    }
    if !symlink_metadata.file_type().is_file() {
        return Err(InspectError::Inspection(format!(
            "input artifact must be a regular file: {}",
            path.display()
        )));
    }

    Ok(())
}

fn detect_artifact_type(path: &Path) -> ArtifactType {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("apk") => ArtifactType::Apk,
        Some("aab") => ArtifactType::Aab,
        Some("ipa") => ArtifactType::Ipa,
        Some("xcarchive") => ArtifactType::Xcarchive,
        _ => ArtifactType::Unknown,
    }
}

fn sha256_file(path: &Path) -> Result<String, InspectError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
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

#[derive(Debug, Clone)]
struct SignatureInspection {
    detected_schemes: Vec<ApkSignatureScheme>,
    certificates: Vec<SignatureCertificate>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct CertificateObservation {
    scheme: ApkSignatureScheme,
    sha256: String,
    size_bytes: usize,
}

fn inspect_signatures(
    path: &Path,
    signature_entries: &[String],
    v1_signature_blocks: &[(String, Vec<u8>)],
) -> Result<SignatureInspection, InspectError> {
    let mut detected_schemes = BTreeSet::new();
    let mut observations = Vec::new();
    let mut warnings = Vec::new();

    if signature_entries
        .iter()
        .any(|entry| is_v1_certificate_signature_entry(entry))
    {
        detected_schemes.insert(ApkSignatureScheme::V1Jar);
    }

    for (entry_name, signature_block) in v1_signature_blocks {
        let mut certificates = extract_v1_signature_certificates(signature_block);
        if certificates.is_empty() {
            warnings.push(format!(
                "no DER certificates were found in v1 signature block {entry_name}"
            ));
        }
        observations.append(&mut certificates);
    }

    match extract_signature_scheme_certificates(path)? {
        Some(extracted) => {
            detected_schemes.extend(extracted.detected_schemes);
            for observation in extracted.certificates {
                detected_schemes.insert(observation.scheme);
                observations.push(observation);
            }
            warnings.extend(extracted.warnings);
        }
        None => {
            if !signature_entries.is_empty() {
                warnings.push(
                    "APK Signature Scheme v2/v3 block was not found; only v1 signature entries were detected"
                        .to_string(),
                );
            }
        }
    }

    Ok(SignatureInspection {
        detected_schemes: detected_schemes.into_iter().collect(),
        certificates: merge_certificate_observations(observations),
        warnings,
    })
}

fn extract_v1_signature_certificates(signature_block: &[u8]) -> Vec<CertificateObservation> {
    extract_der_certificate_slices(signature_block)
        .into_iter()
        .map(|certificate| CertificateObservation {
            scheme: ApkSignatureScheme::V1Jar,
            sha256: sha256_bytes(certificate),
            size_bytes: certificate.len(),
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ExtractedSignatureCertificates {
    detected_schemes: Vec<ApkSignatureScheme>,
    certificates: Vec<CertificateObservation>,
    warnings: Vec<String>,
}

fn extract_signature_scheme_certificates(
    path: &Path,
) -> Result<Option<ExtractedSignatureCertificates>, InspectError> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let Some(central_directory_offset) = find_central_directory_offset(&mut file, file_size)?
    else {
        return Ok(None);
    };

    if central_directory_offset < 24 {
        return Ok(None);
    }

    file.seek(SeekFrom::Start(central_directory_offset - 24))?;
    let mut footer = [0u8; 24];
    file.read_exact(&mut footer)?;
    if &footer[8..24] != APK_SIGNING_BLOCK_MAGIC {
        return Ok(None);
    }

    let block_size = read_le_u64(&footer, 0)?;
    let total_block_size = block_size
        .checked_add(8)
        .ok_or_else(|| InspectError::Inspection("APK Signing Block size overflow".to_string()))?;
    if total_block_size > MAX_APK_SIGNING_BLOCK_BYTES {
        return Err(InspectError::Inspection(format!(
            "APK Signing Block size {} exceeds limit {}",
            total_block_size, MAX_APK_SIGNING_BLOCK_BYTES
        )));
    }
    if total_block_size > central_directory_offset {
        return Err(InspectError::Inspection(
            "APK Signing Block starts before the beginning of the file".to_string(),
        ));
    }

    let block_start = central_directory_offset - total_block_size;
    file.seek(SeekFrom::Start(block_start))?;
    let mut block = vec![0u8; total_block_size as usize];
    file.read_exact(&mut block)?;

    let leading_size = read_le_u64(&block, 0)?;
    if leading_size != block_size {
        return Err(InspectError::Inspection(
            "APK Signing Block leading and trailing sizes do not match".to_string(),
        ));
    }

    let pairs_end = block
        .len()
        .checked_sub(24)
        .ok_or_else(|| InspectError::Inspection("APK Signing Block is too small".to_string()))?;
    let mut pair_offset = 8usize;
    let mut detected_schemes = BTreeSet::new();
    let mut certificates = Vec::new();
    let mut warnings = Vec::new();

    while pair_offset < pairs_end {
        let pair_size = read_le_u64(&block, pair_offset)?;
        pair_offset += 8;

        let pair_size = usize::try_from(pair_size).map_err(|_| {
            InspectError::Inspection(
                "APK Signing Block pair size exceeds platform limits".to_string(),
            )
        })?;
        if pair_size < 4 {
            return Err(InspectError::Inspection(
                "APK Signing Block pair size is too small".to_string(),
            ));
        }
        let pair_end = pair_offset.checked_add(pair_size).ok_or_else(|| {
            InspectError::Inspection("APK Signing Block pair offset overflow".to_string())
        })?;
        if pair_end > pairs_end {
            return Err(InspectError::Inspection(
                "APK Signing Block pair extends beyond block".to_string(),
            ));
        }

        let pair_id = read_le_u32(&block, pair_offset)?;
        let value = &block[pair_offset + 4..pair_end];
        match pair_id {
            APK_SIG_SCHEME_V2_BLOCK_ID => {
                detected_schemes.insert(ApkSignatureScheme::V2);
                match parse_signature_scheme_block(value, ApkSignatureScheme::V2) {
                    Ok(mut parsed) => certificates.append(&mut parsed),
                    Err(error) => warnings.push(format!(
                        "failed to parse APK Signature Scheme v2 block: {error}"
                    )),
                }
            }
            APK_SIG_SCHEME_V3_BLOCK_ID => {
                detected_schemes.insert(ApkSignatureScheme::V3);
                match parse_signature_scheme_block(value, ApkSignatureScheme::V3) {
                    Ok(mut parsed) => certificates.append(&mut parsed),
                    Err(error) => warnings.push(format!(
                        "failed to parse APK Signature Scheme v3 block: {error}"
                    )),
                }
            }
            _ => {}
        }

        pair_offset = pair_end;
    }

    Ok(Some(ExtractedSignatureCertificates {
        detected_schemes: detected_schemes.into_iter().collect(),
        certificates,
        warnings,
    }))
}

fn find_central_directory_offset(
    file: &mut File,
    file_size: u64,
) -> Result<Option<u64>, InspectError> {
    let tail_len = file_size.min(22 + u16::MAX as u64) as usize;
    if tail_len < 22 {
        return Ok(None);
    }

    file.seek(SeekFrom::End(-(tail_len as i64)))?;
    let mut tail = vec![0u8; tail_len];
    file.read_exact(&mut tail)?;

    for offset in (0..=tail.len() - 22).rev() {
        if &tail[offset..offset + 4] != EOCD_SIGNATURE {
            continue;
        }
        let comment_len = read_le_u16(&tail, offset + 20)? as usize;
        if offset + 22 + comment_len != tail.len() {
            continue;
        }
        let central_directory_offset = read_le_u32(&tail, offset + 16)?;
        if central_directory_offset == u32::MAX {
            return Err(InspectError::Inspection(
                "ZIP64 APK central directory offsets are not supported".to_string(),
            ));
        }
        return Ok(Some(central_directory_offset as u64));
    }

    Ok(None)
}

fn parse_signature_scheme_block(
    value: &[u8],
    scheme: ApkSignatureScheme,
) -> Result<Vec<CertificateObservation>, String> {
    let mut offset = 0usize;
    let signers = read_length_prefixed_slice(value, &mut offset, "signers")?;
    if offset != value.len() {
        return Err("trailing data after signers sequence".to_string());
    }

    let mut signer_offset = 0usize;
    let mut observations = Vec::new();
    while signer_offset < signers.len() {
        let signer = read_length_prefixed_slice(signers, &mut signer_offset, "signer")?;
        let mut offset = 0usize;
        let signed_data = read_length_prefixed_slice(signer, &mut offset, "signed data")?;
        observations.extend(parse_signed_data_certificates(signed_data, scheme)?);
    }

    Ok(observations)
}

fn parse_signed_data_certificates(
    signed_data: &[u8],
    scheme: ApkSignatureScheme,
) -> Result<Vec<CertificateObservation>, String> {
    let mut offset = 0usize;
    let _digests = read_length_prefixed_slice(signed_data, &mut offset, "digests")?;
    let certificates = read_length_prefixed_slice(signed_data, &mut offset, "certificates")?;

    let mut certificate_offset = 0usize;
    let mut observations = Vec::new();
    while certificate_offset < certificates.len() {
        let certificate =
            read_length_prefixed_slice(certificates, &mut certificate_offset, "certificate")?;
        if certificate.is_empty() {
            return Err("certificate entry is empty".to_string());
        }
        observations.push(CertificateObservation {
            scheme,
            sha256: sha256_bytes(certificate),
            size_bytes: certificate.len(),
        });
    }

    Ok(observations)
}

fn read_length_prefixed_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    label: &str,
) -> Result<&'a [u8], String> {
    let len = read_u32_from_slice(bytes, *offset)
        .map_err(|error| format!("{label} length is unavailable: {error}"))? as usize;
    *offset = (*offset)
        .checked_add(4)
        .ok_or_else(|| format!("{label} offset overflow"))?;
    let end = (*offset)
        .checked_add(len)
        .ok_or_else(|| format!("{label} end offset overflow"))?;
    if end > bytes.len() {
        return Err(format!(
            "{label} length {len} exceeds remaining {} bytes",
            bytes.len().saturating_sub(*offset)
        ));
    }

    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

fn merge_certificate_observations(
    observations: Vec<CertificateObservation>,
) -> Vec<SignatureCertificate> {
    let mut merged = BTreeMap::<String, SignatureCertificate>::new();

    for observation in observations {
        let certificate =
            merged
                .entry(observation.sha256.clone())
                .or_insert_with(|| SignatureCertificate {
                    sha256: observation.sha256,
                    schemes: Vec::new(),
                    size_bytes: observation.size_bytes,
                });
        if !certificate.schemes.contains(&observation.scheme) {
            certificate.schemes.push(observation.scheme);
            certificate.schemes.sort();
        }
        certificate.size_bytes = certificate.size_bytes.max(observation.size_bytes);
    }

    merged.into_values().collect()
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, InspectError> {
    require_slice_len(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, InspectError> {
    require_slice_len(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64, InspectError> {
    require_slice_len(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]))
}

fn read_u32_from_slice(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    if offset.checked_add(4).map_or(true, |end| end > bytes.len()) {
        return Err("truncated u32");
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn require_slice_len(bytes: &[u8], offset: usize, len: usize) -> Result<(), InspectError> {
    if offset
        .checked_add(len)
        .map_or(true, |end| end > bytes.len())
    {
        return Err(InspectError::Inspection(
            "truncated APK signing metadata".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerElement {
    first_tag_byte: u8,
    content_start: usize,
    content_end: usize,
    total_start: usize,
    total_end: usize,
}

fn extract_der_certificate_slices(bytes: &[u8]) -> Vec<&[u8]> {
    let mut ranges = Vec::new();
    scan_der_for_certificate_ranges(bytes, 0, bytes.len(), 0, &mut ranges);
    ranges.sort_unstable();
    ranges.dedup();

    ranges
        .into_iter()
        .map(|(start, end)| &bytes[start..end])
        .collect()
}

fn scan_der_for_certificate_ranges(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    if depth > 64 || start >= end || end > bytes.len() {
        return;
    }

    let mut offset = start;
    while offset < end {
        let Ok(element) = read_der_element(bytes, offset) else {
            break;
        };
        if element.total_end > end || element.total_end <= offset {
            break;
        }

        if element.first_tag_byte == 0x30
            && looks_like_x509_certificate(&bytes[element.total_start..element.total_end])
        {
            ranges.push((element.total_start, element.total_end));
        }

        if is_constructed_der_tag(element.first_tag_byte) {
            scan_der_for_certificate_ranges(
                bytes,
                element.content_start,
                element.content_end,
                depth + 1,
                ranges,
            );
        }

        offset = element.total_end;
    }
}

fn looks_like_x509_certificate(bytes: &[u8]) -> bool {
    let Ok(certificate) = read_der_element(bytes, 0) else {
        return false;
    };
    if certificate.first_tag_byte != 0x30 || certificate.total_end != bytes.len() {
        return false;
    }

    let Ok(tbs_certificate) = read_der_element(bytes, certificate.content_start) else {
        return false;
    };
    if tbs_certificate.first_tag_byte != 0x30 {
        return false;
    }

    let Ok(signature_algorithm) = read_der_element(bytes, tbs_certificate.total_end) else {
        return false;
    };
    if signature_algorithm.first_tag_byte != 0x30 {
        return false;
    }

    let Ok(signature_value) = read_der_element(bytes, signature_algorithm.total_end) else {
        return false;
    };
    if signature_value.first_tag_byte != 0x03
        || signature_value.total_end != certificate.content_end
    {
        return false;
    }

    looks_like_tbs_certificate(
        bytes,
        tbs_certificate.content_start,
        tbs_certificate.content_end,
    )
}

fn looks_like_tbs_certificate(bytes: &[u8], start: usize, end: usize) -> bool {
    let mut offset = start;
    let Ok(first) = read_der_element(bytes, offset) else {
        return false;
    };
    if first.first_tag_byte == 0xa0 {
        offset = first.total_end;
    }

    let expected_tags = [0x02, 0x30, 0x30, 0x30, 0x30, 0x30];
    for expected_tag in expected_tags {
        let Ok(element) = read_der_element(bytes, offset) else {
            return false;
        };
        if element.total_end > end || element.first_tag_byte != expected_tag {
            return false;
        }
        offset = element.total_end;
    }

    true
}

fn read_der_element(bytes: &[u8], offset: usize) -> Result<DerElement, String> {
    if offset >= bytes.len() {
        return Err("DER element tag is truncated".to_string());
    }

    let first_tag_byte = bytes[offset];
    let tag_len = der_tag_len(bytes, offset)?;
    let length_offset = offset
        .checked_add(tag_len)
        .ok_or_else(|| "DER tag offset overflow".to_string())?;
    let (content_len, length_len) = der_content_len(bytes, length_offset)?;
    let content_start = length_offset
        .checked_add(length_len)
        .ok_or_else(|| "DER content offset overflow".to_string())?;
    let content_end = content_start
        .checked_add(content_len)
        .ok_or_else(|| "DER content end overflow".to_string())?;
    if content_end > bytes.len() {
        return Err("DER content is truncated".to_string());
    }

    Ok(DerElement {
        first_tag_byte,
        content_start,
        content_end,
        total_start: offset,
        total_end: content_end,
    })
}

fn der_tag_len(bytes: &[u8], offset: usize) -> Result<usize, String> {
    let first = bytes[offset];
    if first & 0x1f != 0x1f {
        return Ok(1);
    }

    let mut current = offset
        .checked_add(1)
        .ok_or_else(|| "DER high-tag offset overflow".to_string())?;
    while current < bytes.len() {
        let byte = bytes[current];
        current += 1;
        if byte & 0x80 == 0 {
            return Ok(current - offset);
        }
    }

    Err("DER high-tag-number form is truncated".to_string())
}

fn der_content_len(bytes: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= bytes.len() {
        return Err("DER length is truncated".to_string());
    }

    let first = bytes[offset];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }

    let length_octets = (first & 0x7f) as usize;
    if length_octets == 0 {
        return Err("DER indefinite length is not allowed".to_string());
    }
    if length_octets > std::mem::size_of::<usize>() {
        return Err("DER length exceeds platform limits".to_string());
    }

    let length_start = offset
        .checked_add(1)
        .ok_or_else(|| "DER length offset overflow".to_string())?;
    let length_end = length_start
        .checked_add(length_octets)
        .ok_or_else(|| "DER length end overflow".to_string())?;
    if length_end > bytes.len() {
        return Err("DER long-form length is truncated".to_string());
    }
    if bytes[length_start] == 0 {
        return Err("DER length is not minimally encoded".to_string());
    }

    let mut length = 0usize;
    for byte in &bytes[length_start..length_end] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as usize))
            .ok_or_else(|| "DER length overflow".to_string())?;
    }

    if length < 128 {
        return Err("DER length should have used short form".to_string());
    }

    Ok((length, 1 + length_octets))
}

fn is_constructed_der_tag(first_tag_byte: u8) -> bool {
    first_tag_byte & 0x20 != 0
}

fn is_dex_path(path: &str) -> bool {
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

fn dex_order(path: &str) -> u32 {
    if path == "classes.dex" {
        return 1;
    }

    path.strip_prefix("classes")
        .and_then(|value| value.strip_suffix(".dex"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(u32::MAX)
}

fn native_library_from_entry(
    path: &str,
    size_bytes: u64,
    compressed: bool,
) -> Option<NativeLibrary> {
    let mut parts = path.split('/');
    let lib_dir = parts.next()?;
    let abi = parts.next()?;
    let name = parts.next()?;
    if lib_dir != "lib" || parts.next().is_some() || !name.ends_with(".so") {
        return None;
    }

    Some(NativeLibrary {
        path: path.to_string(),
        abi: abi.to_string(),
        name: name.to_string(),
        size_bytes,
        compressed,
    })
}

fn is_signature_entry(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    upper.starts_with("META-INF/")
        && (upper.ends_with(".RSA")
            || upper.ends_with(".DSA")
            || upper.ends_with(".EC")
            || upper.ends_with(".SF"))
}

fn is_v1_certificate_signature_entry(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    upper.starts_with("META-INF/")
        && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
}

fn is_javascript_bundle_path(path: &str) -> bool {
    path == "assets/index.android.bundle"
        || path.ends_with(".android.bundle")
        || path.ends_with("/index.android.bundle")
        || path.ends_with(".hbc")
}

fn is_flutter_asset_entry(path: &str) -> bool {
    path.starts_with("assets/flutter_assets/") && !path.ends_with('/')
}

fn supported_abis(native_libraries: &[NativeLibrary]) -> Vec<String> {
    let mut abis = BTreeSet::new();
    for library in native_libraries {
        abis.insert(library.abi.clone());
    }
    abis.into_iter().collect()
}

fn detect_flutter(
    native_libraries: &[NativeLibrary],
    flutter_asset_entries: &[String],
) -> Option<FlutterInfo> {
    let mut app_libraries = Vec::new();
    let mut engine_libraries = Vec::new();
    for library in native_libraries {
        if library.name == "libapp.so" {
            app_libraries.push(library.path.clone());
        }
        if library.name == "libflutter.so" {
            engine_libraries.push(library.path.clone());
        }
    }

    if app_libraries.is_empty() && engine_libraries.is_empty() && flutter_asset_entries.is_empty() {
        return None;
    }

    let mut asset_entries = flutter_asset_entries.to_vec();
    asset_entries.sort();

    Some(FlutterInfo {
        detected: true,
        app_libraries,
        engine_libraries,
        asset_entries,
    })
}

fn detect_react_native_engine(
    entry_names: &[String],
    native_libraries: &[NativeLibrary],
    javascript_bundle_path: Option<&str>,
) -> Option<ReactNativeEngine> {
    let has_hermes = native_libraries
        .iter()
        .any(|library| library.name.contains("hermes"))
        || entry_names.iter().any(|path| path.ends_with(".hbc"));
    if has_hermes {
        return Some(ReactNativeEngine::Hermes);
    }

    let has_jsc = native_libraries
        .iter()
        .any(|library| library.name.contains("jsc") || library.name.contains("jscexecutor"));
    if has_jsc {
        return Some(ReactNativeEngine::JavaScriptCore);
    }

    if javascript_bundle_path.is_some()
        || entry_names
            .iter()
            .any(|path| path.contains("libreactnative") || path.contains("reactnative"))
    {
        return Some(ReactNativeEngine::UnknownReactNative);
    }

    None
}

fn detect_security_products(entry_names: &[String]) -> Vec<String> {
    let product_markers: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("Appdome", &["libappdome", "appdome"] as &[&str]),
        ("DexGuard", &["dexguard", "libdexguard"]),
        ("Promon Shield", &["promon", "libpromon"]),
        ("SecNeo", &["secneo", "libsecneo"]),
        ("LIAPP", &["liapp", "libliapp"]),
    ]);

    let lower_entries: Vec<String> = entry_names
        .iter()
        .map(|entry_name| entry_name.to_ascii_lowercase())
        .collect();
    let mut detected = Vec::new();
    for (product, markers) in product_markers {
        if lower_entries
            .iter()
            .any(|entry_name| markers.iter().any(|marker| entry_name.contains(marker)))
        {
            detected.push(product.to_string());
        }
    }
    detected
}

#[cfg(test)]
mod tests {
    use super::{
        detect_flutter, detect_react_native_engine, dex_order, extract_v1_signature_certificates,
        hex_lower, is_dex_path, is_flutter_asset_entry, is_javascript_bundle_path,
        is_v1_certificate_signature_entry, merge_certificate_observations,
        native_library_from_entry, sha256_bytes, ApkSignatureScheme, CertificateObservation,
        ReactNativeEngine,
    };

    #[test]
    fn detects_dex_paths() {
        assert!(is_dex_path("classes.dex"));
        assert!(is_dex_path("classes2.dex"));
        assert!(!is_dex_path("classes.dex.bak"));
        assert!(!is_dex_path("assets/classes.dex"));
    }

    #[test]
    fn orders_dex_paths_numerically() {
        assert!(dex_order("classes.dex") < dex_order("classes2.dex"));
        assert!(dex_order("classes9.dex") < dex_order("classes10.dex"));
    }

    #[test]
    fn extracts_native_library_metadata() {
        let library = native_library_from_entry("lib/arm64-v8a/libsecurity.so", 10, false)
            .expect("native library");
        assert_eq!(library.abi, "arm64-v8a");
        assert_eq!(library.name, "libsecurity.so");
    }

    #[test]
    fn detects_javascript_bundle_paths() {
        assert!(is_javascript_bundle_path("assets/index.android.bundle"));
        assert!(is_javascript_bundle_path("assets/main.hbc"));
        assert!(!is_javascript_bundle_path("assets/image.png"));
    }

    #[test]
    fn detects_hermes_from_native_library() {
        let library = native_library_from_entry("lib/arm64-v8a/libhermes.so", 10, false)
            .expect("native library");
        let engine = detect_react_native_engine(&[], &[library], None);
        assert_eq!(engine, Some(ReactNativeEngine::Hermes));
    }

    #[test]
    fn detects_flutter_from_assets_and_native_libraries() {
        assert!(is_flutter_asset_entry(
            "assets/flutter_assets/AssetManifest.json"
        ));
        assert!(!is_flutter_asset_entry("assets/index.android.bundle"));

        let app = native_library_from_entry("lib/arm64-v8a/libapp.so", 10, false)
            .expect("native library");
        let engine = native_library_from_entry("lib/arm64-v8a/libflutter.so", 10, false)
            .expect("native library");
        let flutter = detect_flutter(
            &[app, engine],
            &["assets/flutter_assets/kernel_blob.bin".to_string()],
        )
        .expect("flutter should be detected");

        assert!(flutter.detected);
        assert_eq!(flutter.app_libraries, vec!["lib/arm64-v8a/libapp.so"]);
        assert_eq!(
            flutter.engine_libraries,
            vec!["lib/arm64-v8a/libflutter.so"]
        );
        assert_eq!(
            flutter.asset_entries,
            vec!["assets/flutter_assets/kernel_blob.bin"]
        );
    }

    #[test]
    fn formats_hex_lowercase() {
        assert_eq!(hex_lower(&[0x00, 0x7f, 0xff]), "007fff");
    }

    #[test]
    fn identifies_v1_certificate_signature_entries() {
        assert!(is_v1_certificate_signature_entry("META-INF/CERT.RSA"));
        assert!(is_v1_certificate_signature_entry("META-INF/CERT.EC"));
        assert!(!is_v1_certificate_signature_entry("META-INF/CERT.SF"));
    }

    #[test]
    fn merges_certificate_observations_by_digest() {
        let certificates = merge_certificate_observations(vec![
            CertificateObservation {
                scheme: ApkSignatureScheme::V2,
                sha256: "a".repeat(64),
                size_bytes: 100,
            },
            CertificateObservation {
                scheme: ApkSignatureScheme::V3,
                sha256: "a".repeat(64),
                size_bytes: 100,
            },
        ]);

        assert_eq!(certificates.len(), 1);
        assert_eq!(
            certificates[0].schemes,
            vec![ApkSignatureScheme::V2, ApkSignatureScheme::V3]
        );
    }

    #[test]
    fn extracts_v1_certificate_digest_from_der_signature_block() {
        let certificate = fake_certificate_der();
        let content_type = der(0x06, &[0x2a]);
        let signed_data = der(0xa0, certificate.as_slice());
        let signature_content = [content_type, signed_data].concat();
        let signature_block = der(0x30, &signature_content);

        let certificates = extract_v1_signature_certificates(&signature_block);

        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].scheme, ApkSignatureScheme::V1Jar);
        assert_eq!(certificates[0].sha256, sha256_bytes(&certificate));
    }

    fn fake_certificate_der() -> Vec<u8> {
        let serial_number = der(0x02, &[0x01]);
        let signature_algorithm = der(0x30, &[]);
        let issuer = der(0x30, &[]);
        let validity = der(0x30, &[]);
        let subject = der(0x30, &[]);
        let subject_public_key_info = der(0x30, &[]);
        let tbs_content = [
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject,
            subject_public_key_info,
        ]
        .concat();
        let tbs_certificate = der(0x30, &tbs_content);
        let certificate_signature_algorithm = der(0x30, &[]);
        let signature_value = der(0x03, &[0x00]);
        let certificate_content = [
            tbs_certificate,
            certificate_signature_algorithm,
            signature_value,
        ]
        .concat();

        der(0x30, &certificate_content)
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if content.len() < 128 {
            output.push(content.len() as u8);
        } else {
            let mut length_bytes = Vec::new();
            let mut length = content.len();
            while length > 0 {
                length_bytes.push((length & 0xff) as u8);
                length >>= 8;
            }
            length_bytes.reverse();
            output.push(0x80 | length_bytes.len() as u8);
            output.extend(length_bytes);
        }
        output.extend_from_slice(content);
        output
    }
}
