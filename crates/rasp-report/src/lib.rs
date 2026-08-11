use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const VERIFICATION_REPORT_SCHEMA_VERSION: u32 = 1;
pub const SIGNING_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const VERIFICATION_TEMPLATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub result: VerificationResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<ArtifactDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<VerificationApplication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<VerificationPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<VerificationSigning>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checks: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationResult {
    Pass,
    Fail,
    NotImplemented,
}

impl VerificationReport {
    pub fn not_implemented() -> Self {
        Self {
            schema_version: VERIFICATION_REPORT_SCHEMA_VERSION,
            result: VerificationResult::NotImplemented,
            input: None,
            application: None,
            payload: None,
            signing: None,
            checks: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadDescriptor {
    pub version: String,
    pub bootstrap_dex_entry: String,
    pub native_library_entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationApplication {
    pub package_name: Option<String>,
    pub provider_name: Option<String>,
    pub provider_authorities: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationPayload {
    pub integrity_manifest_entry: String,
    pub protected_assets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationSigning {
    pub expected_certificate_sha256: Option<String>,
    pub matched_certificate_sha256: Option<String>,
    pub detected_signature_schemes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalSigningRequest {
    pub schema_version: u32,
    pub request_type: SigningRequestType,
    pub original_apk: ArtifactDescriptor,
    pub unsigned_apk: ArtifactDescriptor,
    pub payload: PayloadDescriptor,
    pub signing: ExternalSigningDetails,
    pub generated_by: ToolDescriptor,
    pub instructions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SigningRequestType {
    AndroidApkExternalSigning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalSigningDetails {
    pub expected_certificate_sha256: String,
    pub preserve_signature_lineage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolDescriptor {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationTemplate {
    pub schema_version: u32,
    pub signed_apk: VerificationArtifactPlaceholder,
    pub unsigned_apk: ArtifactDescriptor,
    pub expected_certificate_sha256: String,
    pub expected_payload: PayloadDescriptor,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationArtifactPlaceholder {
    pub path: String,
    pub sha256: Option<String>,
}

impl ExternalSigningRequest {
    pub fn new(
        original_apk: ArtifactDescriptor,
        unsigned_apk: ArtifactDescriptor,
        payload: PayloadDescriptor,
        signing: ExternalSigningDetails,
        generated_by: ToolDescriptor,
    ) -> Self {
        Self {
            schema_version: SIGNING_REQUEST_SCHEMA_VERSION,
            request_type: SigningRequestType::AndroidApkExternalSigning,
            original_apk,
            unsigned_apk,
            payload,
            signing,
            generated_by,
            instructions: vec![
                "Align the unsigned APK with zipalign before signing.".to_string(),
                "Sign the aligned APK with apksigner using the expected certificate.".to_string(),
                "Run rasp-cli verify with the expected certificate SHA-256 after signing."
                    .to_string(),
            ],
        }
    }
}

impl VerificationTemplate {
    pub fn new(
        signed_apk_path: String,
        unsigned_apk: ArtifactDescriptor,
        expected_certificate_sha256: String,
        expected_payload: PayloadDescriptor,
    ) -> Self {
        Self {
            schema_version: VERIFICATION_TEMPLATE_SCHEMA_VERSION,
            signed_apk: VerificationArtifactPlaceholder {
                path: signed_apk_path,
                sha256: None,
            },
            unsigned_apk,
            expected_certificate_sha256,
            expected_payload,
            checks: vec![
                "ZIP structure is valid and contains no duplicate or unsafe paths".to_string(),
                "APK contains the injected bootstrap content provider".to_string(),
                "APK contains the internal integrity manifest".to_string(),
                "APK contains the injected bootstrap DEX".to_string(),
                "APK contains the injected native payload libraries".to_string(),
                "APK signing certificate matches expected_certificate_sha256".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactDescriptor, ExternalSigningDetails, ExternalSigningRequest, PayloadDescriptor,
        ToolDescriptor, VerificationTemplate, SIGNING_REQUEST_SCHEMA_VERSION,
        VERIFICATION_TEMPLATE_SCHEMA_VERSION,
    };

    #[test]
    fn serializes_external_signing_request_shape() {
        let request = ExternalSigningRequest::new(
            artifact("input.apk"),
            artifact("unsigned.apk"),
            payload(),
            ExternalSigningDetails {
                expected_certificate_sha256: "abc123".to_string(),
                preserve_signature_lineage: false,
            },
            ToolDescriptor {
                name: "rasp-cli".to_string(),
                version: "0.1.0".to_string(),
            },
        );

        let value = serde_json::to_value(request).expect("serialize signing request");

        assert_eq!(value["schema_version"], SIGNING_REQUEST_SCHEMA_VERSION);
        assert_eq!(
            value["request_type"],
            "ANDROID_APK_EXTERNAL_SIGNING".to_string()
        );
        assert_eq!(value["unsigned_apk"]["path"], "unsigned.apk");
        assert_eq!(value["payload"]["bootstrap_dex_entry"], "classes2.dex");
    }

    #[test]
    fn serializes_verification_template_shape() {
        let template = VerificationTemplate::new(
            "signed.apk".to_string(),
            artifact("unsigned.apk"),
            "abc123".to_string(),
            payload(),
        );

        let value = serde_json::to_value(template).expect("serialize verification template");

        assert_eq!(
            value["schema_version"],
            VERIFICATION_TEMPLATE_SCHEMA_VERSION
        );
        assert_eq!(value["signed_apk"]["path"], "signed.apk");
        assert_eq!(value["signed_apk"]["sha256"], serde_json::Value::Null);
        assert_eq!(
            value["expected_payload"]["native_library_entries"][0],
            "lib/arm64-v8a/libsecurity.so"
        );
    }

    fn artifact(path: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            path: path.to_string(),
            sha256: "0".repeat(64),
            size_bytes: 1,
        }
    }

    fn payload() -> PayloadDescriptor {
        PayloadDescriptor {
            version: "dev".to_string(),
            bootstrap_dex_entry: "classes2.dex".to_string(),
            native_library_entries: vec!["lib/arm64-v8a/libsecurity.so".to_string()],
        }
    }
}
