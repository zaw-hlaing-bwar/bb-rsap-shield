use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PAYLOAD_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const PAYLOAD_MANIFEST_FILE: &str = "manifest.json";
pub const PAYLOAD_SIGNATURE_FILE: &str = "signature.ed25519";
pub const BOOTSTRAP_DEX_FILE: &str = "bootstrap.dex";
pub const SECURITY_LIBRARY_NAME: &str = "libsecurity.so";
pub const PAYLOAD_SBOM_FILE: &str = "sbom.json";
pub const PAYLOAD_LICENSE_NOTICE_FILE: &str = "licenses/NOTICE.txt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadManifest {
    pub payload_version: String,
    pub minimum_cli_version: String,
    pub maximum_cli_version: String,
    pub supported_platform: String,
    pub supported_abis: Vec<String>,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadSbom {
    pub schema_version: u32,
    pub sbom_type: String,
    pub payload_version: String,
    pub components: Vec<PayloadSbomComponent>,
    pub generated_by: PayloadSbomTool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadSbomComponent {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    pub path: String,
    pub sha256: String,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadSbomTool {
    pub name: String,
    pub version: String,
}

impl PayloadManifest {
    pub fn supports_android(&self) -> bool {
        self.supported_platform == "android"
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PayloadPackError {
    #[error("failed to access payload pack: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse payload manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("payload pack validation failed: {0}")]
    Validation(String),
    #[error("payload file digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("invalid payload signing public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid payload signing key: {0}")]
    InvalidSigningKey(String),
    #[error("payload signature verification failed: {0}")]
    InvalidSignature(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPack {
    pub root: PathBuf,
    pub manifest: PayloadManifest,
    pub signature_path: PathBuf,
    pub bootstrap_dex_path: PathBuf,
    pub abi_libraries: BTreeMap<String, PathBuf>,
}

impl PayloadPack {
    pub fn library_for_abi(&self, abi: &str) -> Option<&Path> {
        self.abi_libraries.get(abi).map(PathBuf::as_path)
    }
}

#[derive(Debug, Clone)]
pub struct PayloadVerificationKey {
    verifying_key: VerifyingKey,
}

#[derive(Debug, Clone)]
pub struct PayloadSigningKey {
    signing_key: SigningKey,
}

impl PayloadVerificationKey {
    pub fn from_hex(value: &str) -> Result<Self, PayloadPackError> {
        let bytes = decode_fixed_hex::<32>(value).map_err(PayloadPackError::InvalidPublicKey)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PayloadPackError> {
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|error| PayloadPackError::InvalidPublicKey(error.to_string()))?;
        Ok(Self { verifying_key })
    }
}

impl PayloadSigningKey {
    pub fn from_hex(value: &str) -> Result<Self, PayloadPackError> {
        let bytes = decode_fixed_hex::<32>(value).map_err(PayloadPackError::InvalidSigningKey)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex_lower(self.signing_key.verifying_key().as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPackBuildOptions {
    pub output_root: PathBuf,
    pub bootstrap_dex_path: PathBuf,
    pub abi_libraries: BTreeMap<String, PathBuf>,
    pub payload_version: String,
    pub minimum_cli_version: String,
    pub maximum_cli_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPackBuildReport {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
    pub payload_version: String,
    pub supported_abis: Vec<String>,
    pub files: BTreeMap<String, String>,
    pub payload_signing_public_key_hex: String,
}

pub fn load_payload_pack(
    root: impl AsRef<Path>,
    cli_version: &str,
) -> Result<PayloadPack, PayloadPackError> {
    load_payload_pack_internal(root, cli_version, None)
}

pub fn load_payload_pack_verified(
    root: impl AsRef<Path>,
    cli_version: &str,
    verification_key: &PayloadVerificationKey,
) -> Result<PayloadPack, PayloadPackError> {
    load_payload_pack_internal(root, cli_version, Some(verification_key))
}

pub fn build_payload_pack(
    options: &PayloadPackBuildOptions,
    signing_key: &PayloadSigningKey,
) -> Result<PayloadPackBuildReport, PayloadPackError> {
    validate_build_options(options)?;

    let root = &options.output_root;
    fs::create_dir_all(root)?;

    validate_bootstrap_dex(&options.bootstrap_dex_path)?;
    let mut files = BTreeMap::new();
    files.insert(
        BOOTSTRAP_DEX_FILE.to_string(),
        copy_payload_file(&options.bootstrap_dex_path, &root.join(BOOTSTRAP_DEX_FILE))?,
    );

    let supported_abis = options.abi_libraries.keys().cloned().collect::<Vec<_>>();
    for (abi, source_library) in &options.abi_libraries {
        validate_native_library(source_library)?;
        let relative_path = format!("{abi}/{SECURITY_LIBRARY_NAME}");
        files.insert(
            relative_path.clone(),
            copy_payload_file(source_library, &root.join(&relative_path))?,
        );
    }
    write_payload_pack_metadata(root, options, &mut files)?;

    let manifest = PayloadManifest {
        payload_version: options.payload_version.clone(),
        minimum_cli_version: options.minimum_cli_version.clone(),
        maximum_cli_version: options.maximum_cli_version.clone(),
        supported_platform: "android".to_string(),
        supported_abis,
        files,
    };
    validate_manifest_metadata(&manifest, &options.minimum_cli_version)?;
    verify_manifest_files(root, &manifest)?;

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_path = root.join(PAYLOAD_MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes)?;

    let signature = signing_key.signing_key.sign(&manifest_bytes);
    let signature_path = root.join(PAYLOAD_SIGNATURE_FILE);
    fs::write(&signature_path, signature.to_bytes())?;

    Ok(PayloadPackBuildReport {
        root: root.clone(),
        manifest_path,
        signature_path,
        payload_version: manifest.payload_version,
        supported_abis: manifest.supported_abis,
        files: manifest.files,
        payload_signing_public_key_hex: signing_key.public_key_hex(),
    })
}

fn load_payload_pack_internal(
    root: impl AsRef<Path>,
    cli_version: &str,
    verification_key: Option<&PayloadVerificationKey>,
) -> Result<PayloadPack, PayloadPackError> {
    let root = root.as_ref();
    let metadata = fs::metadata(root)?;
    if !metadata.is_dir() {
        return Err(PayloadPackError::Validation(format!(
            "payload pack root must be a directory: {}",
            root.display()
        )));
    }

    let manifest_path = root.join(PAYLOAD_MANIFEST_FILE);
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: PayloadManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest_metadata(&manifest, cli_version)?;
    verify_manifest_files(root, &manifest)?;

    let signature_path = root.join(PAYLOAD_SIGNATURE_FILE);
    if !signature_path.is_file() {
        return Err(PayloadPackError::Validation(format!(
            "payload pack is missing {}",
            PAYLOAD_SIGNATURE_FILE
        )));
    }
    if let Some(verification_key) = verification_key {
        verify_payload_signature(&manifest_bytes, &signature_path, verification_key)?;
    }

    let bootstrap_dex_path = root.join(BOOTSTRAP_DEX_FILE);
    if !bootstrap_dex_path.is_file() {
        return Err(PayloadPackError::Validation(format!(
            "payload pack is missing {}",
            BOOTSTRAP_DEX_FILE
        )));
    }

    let mut abi_libraries = BTreeMap::new();
    for abi in &manifest.supported_abis {
        let library_path = format!("{abi}/{SECURITY_LIBRARY_NAME}");
        let absolute_library_path = root.join(&library_path);
        if !absolute_library_path.is_file() {
            return Err(PayloadPackError::Validation(format!(
                "payload pack is missing ABI library {library_path}"
            )));
        }
        abi_libraries.insert(abi.clone(), absolute_library_path);
    }

    Ok(PayloadPack {
        root: root.to_path_buf(),
        manifest,
        signature_path,
        bootstrap_dex_path,
        abi_libraries,
    })
}

fn validate_build_options(options: &PayloadPackBuildOptions) -> Result<(), PayloadPackError> {
    let mut errors = Vec::new();

    if options.output_root.as_os_str().is_empty() {
        errors.push("output root must not be empty".to_string());
    }
    if options.payload_version.trim().is_empty() {
        errors.push("payload_version must not be empty".to_string());
    }
    if options.minimum_cli_version.trim().is_empty() {
        errors.push("minimum_cli_version must not be empty".to_string());
    }
    if options.maximum_cli_version.trim().is_empty() {
        errors.push("maximum_cli_version must not be empty".to_string());
    }
    if options.abi_libraries.is_empty() {
        errors.push("at least one native library must be provided".to_string());
    }
    if !options.bootstrap_dex_path.is_file() {
        errors.push(format!(
            "bootstrap DEX does not exist: {}",
            options.bootstrap_dex_path.display()
        ));
    }

    for (abi, library) in &options.abi_libraries {
        if !is_supported_abi(abi) {
            errors.push(format!("unsupported ABI in payload pack: {abi}"));
        }
        if !library.is_file() {
            errors.push(format!(
                "native library for {abi} does not exist: {}",
                library.display()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(PayloadPackError::Validation(errors.join("; ")))
    }
}

fn validate_bootstrap_dex(path: &Path) -> Result<(), PayloadPackError> {
    validate_magic(path, b"dex\n", "bootstrap DEX")
}

fn validate_native_library(path: &Path) -> Result<(), PayloadPackError> {
    validate_magic(path, b"\x7fELF", "native library")
}

fn validate_magic(path: &Path, expected_magic: &[u8], label: &str) -> Result<(), PayloadPackError> {
    let mut file = fs::File::open(path)?;
    let mut magic = vec![0u8; expected_magic.len()];
    let bytes_read = file.read(&mut magic)?;
    if bytes_read != expected_magic.len() || magic != expected_magic {
        return Err(PayloadPackError::Validation(format!(
            "{label} has invalid file magic: {}",
            path.display()
        )));
    }
    Ok(())
}

fn copy_payload_file(source: &Path, destination: &Path) -> Result<String, PayloadPackError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    let same_file = fs::canonicalize(source).ok() == fs::canonicalize(destination).ok();
    if !same_file {
        fs::copy(source, destination)?;
    }

    sha256_file(destination)
}

fn write_payload_pack_metadata(
    root: &Path,
    options: &PayloadPackBuildOptions,
    files: &mut BTreeMap<String, String>,
) -> Result<(), PayloadPackError> {
    let notice_digest = write_text_payload_file(
        root,
        PAYLOAD_LICENSE_NOTICE_FILE,
        &payload_license_notice(&options.payload_version),
    )?;
    files.insert(PAYLOAD_LICENSE_NOTICE_FILE.to_string(), notice_digest);

    let sbom = build_payload_sbom(options, files);
    let sbom_body = serde_json::to_vec_pretty(&sbom)?;
    let sbom_digest = write_bytes_payload_file(root, PAYLOAD_SBOM_FILE, &sbom_body)?;
    files.insert(PAYLOAD_SBOM_FILE.to_string(), sbom_digest);

    Ok(())
}

fn build_payload_sbom(
    options: &PayloadPackBuildOptions,
    files: &BTreeMap<String, String>,
) -> PayloadSbom {
    let mut components = Vec::new();
    components.push(PayloadSbomComponent {
        name: "rasp-bootstrap".to_string(),
        kind: "android_dex".to_string(),
        abi: None,
        path: BOOTSTRAP_DEX_FILE.to_string(),
        sha256: files.get(BOOTSTRAP_DEX_FILE).cloned().unwrap_or_default(),
        license: "LicenseRef-Proprietary".to_string(),
    });

    for abi in options.abi_libraries.keys() {
        let path = format!("{abi}/{SECURITY_LIBRARY_NAME}");
        components.push(PayloadSbomComponent {
            name: "rasp-security".to_string(),
            kind: "native_library".to_string(),
            abi: Some(abi.clone()),
            path: path.clone(),
            sha256: files.get(&path).cloned().unwrap_or_default(),
            license: "LicenseRef-Proprietary".to_string(),
        });
    }

    components.push(PayloadSbomComponent {
        name: "rasp-payload-license-notice".to_string(),
        kind: "license_notice".to_string(),
        abi: None,
        path: PAYLOAD_LICENSE_NOTICE_FILE.to_string(),
        sha256: files
            .get(PAYLOAD_LICENSE_NOTICE_FILE)
            .cloned()
            .unwrap_or_default(),
        license: "LicenseRef-Proprietary".to_string(),
    });

    PayloadSbom {
        schema_version: 1,
        sbom_type: "RASP_SHIELD_PAYLOAD_SBOM".to_string(),
        payload_version: options.payload_version.clone(),
        components,
        generated_by: PayloadSbomTool {
            name: "payload-pack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    }
}

fn payload_license_notice(payload_version: &str) -> String {
    format!(
        "RASP Shield Android runtime payload\n\nPayload version: {payload_version}\nLicense: LicenseRef-Proprietary\n\nThis payload pack contains RASP Shield bootstrap DEX and native runtime artifacts built from this repository. Add third-party notices here before external distribution.\n"
    )
}

fn write_text_payload_file(
    root: &Path,
    relative_path: &str,
    body: &str,
) -> Result<String, PayloadPackError> {
    write_bytes_payload_file(root, relative_path, body.as_bytes())
}

fn write_bytes_payload_file(
    root: &Path,
    relative_path: &str,
    bytes: &[u8],
) -> Result<String, PayloadPackError> {
    validate_payload_relative_path(relative_path)?;
    let destination = root.join(relative_path);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&destination, bytes)?;
    Ok(sha256_bytes(bytes))
}

fn verify_payload_signature(
    manifest_bytes: &[u8],
    signature_path: &Path,
    verification_key: &PayloadVerificationKey,
) -> Result<(), PayloadPackError> {
    let signature_bytes = parse_signature_file(signature_path)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verification_key
        .verifying_key
        .verify(manifest_bytes, &signature)
        .map_err(|error| PayloadPackError::InvalidSignature(error.to_string()))
}

fn parse_signature_file(path: &Path) -> Result<[u8; 64], PayloadPackError> {
    let bytes = fs::read(path)?;
    if bytes.len() == 64 {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes);
        return Ok(signature);
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| {
        PayloadPackError::InvalidSignature(
            "signature must be 64 raw bytes or 128 hex characters".to_string(),
        )
    })?;
    decode_fixed_hex::<64>(text.trim()).map_err(PayloadPackError::InvalidSignature)
}

fn validate_manifest_metadata(
    manifest: &PayloadManifest,
    cli_version: &str,
) -> Result<(), PayloadPackError> {
    let mut errors = Vec::new();

    if !manifest.supports_android() {
        errors.push(format!(
            "supported_platform must be android, got {}",
            manifest.supported_platform
        ));
    }

    if manifest.payload_version.trim().is_empty() {
        errors.push("payload_version must not be empty".to_string());
    }

    if manifest.supported_abis.is_empty() {
        errors.push("supported_abis must contain at least one ABI".to_string());
    }

    for abi in &manifest.supported_abis {
        if !is_supported_abi(abi) {
            errors.push(format!("unsupported ABI in payload pack: {abi}"));
        }
    }

    if !is_cli_version_compatible(
        cli_version,
        &manifest.minimum_cli_version,
        &manifest.maximum_cli_version,
    ) {
        errors.push(format!(
            "CLI version {cli_version} is outside payload compatibility range {} - {}",
            manifest.minimum_cli_version, manifest.maximum_cli_version
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(PayloadPackError::Validation(errors.join("; ")))
    }
}

fn verify_manifest_files(root: &Path, manifest: &PayloadManifest) -> Result<(), PayloadPackError> {
    for (relative_path, expected_digest) in &manifest.files {
        validate_payload_relative_path(relative_path)?;
        if !is_hex_sha256(expected_digest) {
            return Err(PayloadPackError::Validation(format!(
                "invalid SHA-256 digest for {relative_path}: {expected_digest}"
            )));
        }

        let path = root.join(relative_path);
        if !path.is_file() {
            return Err(PayloadPackError::Validation(format!(
                "payload manifest references missing file {relative_path}"
            )));
        }

        let actual_digest = sha256_file(&path)?;
        if !actual_digest.eq_ignore_ascii_case(expected_digest) {
            return Err(PayloadPackError::DigestMismatch {
                path: relative_path.clone(),
                expected: expected_digest.to_ascii_lowercase(),
                actual: actual_digest,
            });
        }
    }

    validate_required_manifest_entry(manifest, BOOTSTRAP_DEX_FILE)?;
    validate_required_manifest_entry(manifest, PAYLOAD_SBOM_FILE)?;
    validate_required_manifest_entry(manifest, PAYLOAD_LICENSE_NOTICE_FILE)?;
    for abi in &manifest.supported_abis {
        validate_required_manifest_entry(
            manifest,
            format!("{abi}/{SECURITY_LIBRARY_NAME}").as_str(),
        )?;
    }

    Ok(())
}

fn is_supported_abi(abi: &str) -> bool {
    matches!(abi, "arm64-v8a" | "armeabi-v7a" | "x86_64")
}

fn validate_required_manifest_entry(
    manifest: &PayloadManifest,
    relative_path: &str,
) -> Result<(), PayloadPackError> {
    if manifest.files.contains_key(relative_path) {
        Ok(())
    } else {
        Err(PayloadPackError::Validation(format!(
            "payload manifest is missing required file entry {relative_path}"
        )))
    }
}

fn validate_payload_relative_path(relative_path: &str) -> Result<(), PayloadPackError> {
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.starts_with('\\')
        || relative_path.contains('\\')
        || relative_path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(PayloadPackError::Validation(format!(
            "unsafe payload file path {relative_path}"
        )));
    }

    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, PayloadPackError> {
    let mut file = fs::File::open(path)?;
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
    hex_lower(&Sha256::digest(bytes))
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

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let expected_len = N * 2;
    if value.len() != expected_len {
        return Err(format!(
            "expected {expected_len} hex characters, got {}",
            value.len()
        ));
    }

    let mut output = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or_else(|| {
            format!(
                "invalid hex character '{}' at offset {}",
                chunk[0] as char,
                index * 2
            )
        })?;
        let low = hex_nibble(chunk[1]).ok_or_else(|| {
            format!(
                "invalid hex character '{}' at offset {}",
                chunk[1] as char,
                index * 2 + 1
            )
        })?;
        output[index] = (high << 4) | low;
    }

    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_cli_version_compatible(cli_version: &str, minimum: &str, maximum: &str) -> bool {
    let Some(cli_version) = ParsedVersion::parse(cli_version) else {
        return false;
    };
    let Some(minimum) = ParsedVersion::parse(minimum) else {
        return false;
    };

    if cli_version < minimum {
        return false;
    }

    if let Some(prefix) = maximum.strip_suffix(".x") {
        let Some(maximum_major) = prefix.parse::<u64>().ok() else {
            return false;
        };
        return cli_version.major == maximum_major;
    }

    let Some(maximum) = ParsedVersion::parse(maximum) else {
        return false;
    };
    cli_version <= maximum
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl ParsedVersion {
    fn parse(value: &str) -> Option<Self> {
        let normalized = value.split_once('-').map_or(value, |(version, _)| version);
        let mut parts = normalized.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_payload_pack, decode_fixed_hex, hex_lower, is_cli_version_compatible, is_hex_sha256,
        load_payload_pack_verified, parse_signature_file, validate_payload_relative_path,
        ParsedVersion, PayloadPackBuildOptions, PayloadSbom, PayloadSigningKey,
        PayloadVerificationKey, BOOTSTRAP_DEX_FILE, PAYLOAD_LICENSE_NOTICE_FILE, PAYLOAD_SBOM_FILE,
        SECURITY_LIBRARY_NAME,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_simple_versions() {
        assert_eq!(
            ParsedVersion::parse("1.2.3"),
            Some(ParsedVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(
            ParsedVersion::parse("1.2.3-dev"),
            Some(ParsedVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
    }

    #[test]
    fn checks_version_ranges() {
        assert!(is_cli_version_compatible("1.2.0", "1.0.0", "1.x"));
        assert!(is_cli_version_compatible("1.2.0", "1.0.0", "1.9.0"));
        assert!(!is_cli_version_compatible("2.0.0", "1.0.0", "1.x"));
        assert!(!is_cli_version_compatible("0.9.0", "1.0.0", "1.x"));
    }

    #[test]
    fn rejects_unsafe_payload_paths() {
        assert!(validate_payload_relative_path("arm64-v8a/libsecurity.so").is_ok());
        assert!(validate_payload_relative_path("../libsecurity.so").is_err());
        assert!(validate_payload_relative_path("/tmp/libsecurity.so").is_err());
        assert!(validate_payload_relative_path("arm64-v8a\\libsecurity.so").is_err());
    }

    #[test]
    fn validates_sha256_hex() {
        assert!(is_hex_sha256(&"a".repeat(64)));
        assert!(!is_hex_sha256("abc"));
        assert!(!is_hex_sha256(&"g".repeat(64)));
    }

    #[test]
    fn parses_payload_public_key_hex() {
        let bytes = [7u8; 32];
        let public_key = SigningKey::from_bytes(&bytes).verifying_key();
        let hex = hex_lower(public_key.as_bytes());

        let parsed = PayloadVerificationKey::from_hex(&hex).expect("valid public key");

        assert_eq!(parsed.verifying_key.as_bytes(), public_key.as_bytes());
    }

    #[test]
    fn rejects_invalid_fixed_hex() {
        assert_eq!(
            decode_fixed_hex::<2>("abc").expect_err("odd length should fail"),
            "expected 4 hex characters, got 3"
        );
        assert!(decode_fixed_hex::<2>("00xz")
            .expect_err("invalid hex should fail")
            .contains("invalid hex character"));
    }

    #[test]
    fn parses_raw_signature_file() {
        let root = create_temp_dir("raw-signature");
        let signature_path = root.join("signature.ed25519");
        let signature = [3u8; 64];
        fs::write(&signature_path, signature).expect("write signature");

        assert_eq!(
            parse_signature_file(&signature_path).expect("parse signature"),
            signature
        );
    }

    #[test]
    fn parses_hex_signature_file() {
        let root = create_temp_dir("hex-signature");
        let signature_path = root.join("signature.ed25519");
        let signature = [5u8; 64];
        fs::write(&signature_path, format!("{}\n", hex_lower(&signature)))
            .expect("write signature");

        assert_eq!(
            parse_signature_file(&signature_path).expect("parse signature"),
            signature
        );
    }

    #[test]
    fn verifies_signed_payload_pack() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let root = create_signed_payload_pack("verified-pack", &signing_key);
        let verification_key =
            PayloadVerificationKey::from_bytes(*signing_key.verifying_key().as_bytes())
                .expect("valid verification key");

        let pack =
            load_payload_pack_verified(&root, "0.1.0", &verification_key).expect("valid pack");

        assert_eq!(pack.manifest.payload_version, "2026.08.05-dev");
        assert!(pack.bootstrap_dex_path.ends_with(BOOTSTRAP_DEX_FILE));
        assert!(pack.library_for_abi("arm64-v8a").is_some());
    }

    #[test]
    fn builds_and_verifies_payload_pack() {
        let source_root = create_temp_dir("build-sources");
        let output_root = create_temp_dir("build-output");
        let bootstrap_path = source_root.join("classes.dex");
        let library_path = source_root.join("libsecurity.so");
        fs::write(&bootstrap_path, b"dex\n035\0payload").expect("write bootstrap source");
        fs::write(&library_path, b"\x7fELFsecurity library").expect("write native source");

        let signing_key = PayloadSigningKey::from_bytes([13u8; 32]);
        let mut abi_libraries = BTreeMap::new();
        abi_libraries.insert("arm64-v8a".to_string(), library_path);
        let report = build_payload_pack(
            &PayloadPackBuildOptions {
                output_root: output_root.clone(),
                bootstrap_dex_path: bootstrap_path,
                abi_libraries,
                payload_version: "2026.08.09-dev".to_string(),
                minimum_cli_version: "0.1.0".to_string(),
                maximum_cli_version: "0.x".to_string(),
            },
            &signing_key,
        )
        .expect("payload pack should build");

        let verification_key =
            PayloadVerificationKey::from_hex(&report.payload_signing_public_key_hex)
                .expect("public key should parse");
        let pack =
            load_payload_pack_verified(&output_root, "0.1.0", &verification_key).expect("valid");

        assert_eq!(pack.manifest.payload_version, "2026.08.09-dev");
        assert_eq!(pack.manifest.supported_abis, vec!["arm64-v8a"]);
        assert!(output_root.join(BOOTSTRAP_DEX_FILE).is_file());
        assert!(output_root
            .join("arm64-v8a")
            .join(SECURITY_LIBRARY_NAME)
            .is_file());
        assert!(output_root.join(PAYLOAD_SBOM_FILE).is_file());
        assert!(output_root.join(PAYLOAD_LICENSE_NOTICE_FILE).is_file());
        assert!(pack.manifest.files.contains_key(PAYLOAD_SBOM_FILE));
        assert!(pack
            .manifest
            .files
            .contains_key(PAYLOAD_LICENSE_NOTICE_FILE));
        let sbom: PayloadSbom =
            serde_json::from_slice(&fs::read(output_root.join(PAYLOAD_SBOM_FILE)).expect("sbom"))
                .expect("parse sbom");
        assert_eq!(sbom.payload_version, "2026.08.09-dev");
        assert!(sbom
            .components
            .iter()
            .any(|component| component.path == BOOTSTRAP_DEX_FILE));
        assert!(sbom.components.iter().any(|component| {
            component.path == "arm64-v8a/libsecurity.so"
                && component.abi.as_deref() == Some("arm64-v8a")
        }));
        assert!(report.signature_path.is_file());
    }

    #[test]
    fn rejects_invalid_build_artifact_magic() {
        let source_root = create_temp_dir("invalid-build-sources");
        let output_root = create_temp_dir("invalid-build-output");
        let bootstrap_path = source_root.join("classes.dex");
        let library_path = source_root.join("libsecurity.so");
        fs::write(&bootstrap_path, b"not a dex").expect("write bootstrap source");
        fs::write(&library_path, b"\x7fELFsecurity library").expect("write native source");

        let mut abi_libraries = BTreeMap::new();
        abi_libraries.insert("arm64-v8a".to_string(), library_path);
        let error = build_payload_pack(
            &PayloadPackBuildOptions {
                output_root,
                bootstrap_dex_path: bootstrap_path,
                abi_libraries,
                payload_version: "2026.08.09-dev".to_string(),
                minimum_cli_version: "0.1.0".to_string(),
                maximum_cli_version: "0.x".to_string(),
            },
            &PayloadSigningKey::from_bytes([15u8; 32]),
        )
        .expect_err("invalid dex magic should fail");

        assert!(error
            .to_string()
            .contains("bootstrap DEX has invalid file magic"));
    }

    #[test]
    fn rejects_payload_pack_with_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let root = create_signed_payload_pack("invalid-signature-pack", &signing_key);
        let verification_key =
            PayloadVerificationKey::from_bytes(*signing_key.verifying_key().as_bytes())
                .expect("valid verification key");

        let manifest_path = root.join("manifest.json");
        let manifest = fs::read_to_string(&manifest_path).expect("read manifest");
        fs::write(
            manifest_path,
            manifest.replace("2026.08.05-dev", "2026.08.05-tampered"),
        )
        .expect("tamper manifest");

        let error = load_payload_pack_verified(&root, "0.1.0", &verification_key)
            .expect_err("tampered pack should fail");

        assert!(error
            .to_string()
            .contains("payload signature verification failed"));
    }

    fn create_signed_payload_pack(name: &str, signing_key: &SigningKey) -> PathBuf {
        let root = create_temp_dir(name);
        let abi = "arm64-v8a";
        let bootstrap_path = root.join(BOOTSTRAP_DEX_FILE);
        let library_path = root.join(abi).join(SECURITY_LIBRARY_NAME);

        fs::create_dir_all(library_path.parent().expect("library parent")).expect("create ABI dir");
        fs::write(&bootstrap_path, b"dex\n035\0").expect("write bootstrap");
        fs::write(&library_path, b"security library").expect("write native library");
        fs::create_dir_all(root.join("licenses")).expect("create licenses dir");
        let notice = b"test notice";
        fs::write(root.join(PAYLOAD_LICENSE_NOTICE_FILE), notice).expect("write notice");
        let sbom = serde_json::json!({
            "schema_version": 1,
            "sbom_type": "RASP_SHIELD_PAYLOAD_SBOM",
            "payload_version": "2026.08.05-dev",
            "components": [
                {
                    "name": "rasp-bootstrap",
                    "kind": "android_dex",
                    "path": "bootstrap.dex",
                    "sha256": sha256_bytes(b"dex\n035\0"),
                    "license": "LicenseRef-Proprietary"
                }
            ],
            "generated_by": {
                "name": "payload-pack-test",
                "version": "0.1.0"
            }
        });
        let sbom_bytes = serde_json::to_vec_pretty(&sbom).expect("serialize sbom");
        fs::write(root.join(PAYLOAD_SBOM_FILE), &sbom_bytes).expect("write sbom");

        let mut files = BTreeMap::new();
        files.insert(BOOTSTRAP_DEX_FILE.to_string(), sha256_bytes(b"dex\n035\0"));
        files.insert(
            format!("{abi}/{SECURITY_LIBRARY_NAME}"),
            sha256_bytes(b"security library"),
        );
        files.insert(
            PAYLOAD_LICENSE_NOTICE_FILE.to_string(),
            sha256_bytes(notice),
        );
        files.insert(PAYLOAD_SBOM_FILE.to_string(), sha256_bytes(&sbom_bytes));

        let manifest = serde_json::json!({
            "payload_version": "2026.08.05-dev",
            "minimum_cli_version": "0.1.0",
            "maximum_cli_version": "0.x",
            "supported_platform": "android",
            "supported_abis": [abi],
            "files": files,
        });
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest for test pack");
        fs::write(root.join("manifest.json"), &manifest_bytes).expect("write manifest");

        let signature = signing_key.sign(&manifest_bytes);
        fs::write(root.join("signature.ed25519"), signature.to_bytes()).expect("write signature");

        root
    }

    fn create_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rasp-payload-pack-{name}-{nonce}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }
}
