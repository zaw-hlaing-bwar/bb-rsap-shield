use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use android_apk::{
    rewrite_unsigned_apk_with_payload, ApkRewriteError, ApkRewriteOptions, IntegrityApkInventory,
    IntegrityManifest, IntegrityManifestInput, IntegrityProtectedAssetKind, IntegrityRiskAction,
    IntegrityRiskThresholds, IntegrityRuntimeMonitoring, IntegrityRuntimePolicy, IntegrityTool,
    PayloadFiles, INTEGRITY_MANIFEST_ENTRY,
};
use android_signing::{
    align_apk, sign_apk, verify_alignment, verify_apk_signature, AndroidSigningTools,
    ApkSignOptions, SigningToolError,
};
use artifact_inspector::{inspect_apk, ApkSignatureScheme, InspectionResult};
use clap::{Args, Parser, Subcommand, ValueEnum};
use payload_pack::{
    build_payload_pack, load_payload_pack_verified, PayloadPackBuildOptions, PayloadPackError,
    PayloadSigningKey, PayloadVerificationKey,
};
use rasp_config::{
    is_valid_env_var_name, load_config, RaspConfig, RiskAction, CONFIG_SCHEMA_VERSION,
};
use rasp_core::{ExitCode, RaspError, RaspResult};
use rasp_report::{
    ArtifactDescriptor, ExternalSigningDetails, ExternalSigningRequest, PayloadDescriptor,
    ToolDescriptor, VerificationApplication, VerificationPayload, VerificationReport,
    VerificationResult, VerificationSigning, VerificationTemplate,
    VERIFICATION_REPORT_SCHEMA_VERSION,
};
use runtime_test::{
    run_runtime_smoke_test, AdbTool, RuntimeSmokeError, RuntimeSmokeTestPlan,
    RuntimeSmokeTestReport, RuntimeSmokeTestResult,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "rasp-cli")]
#[command(about = "Post-build Android APK hardening CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect an input artifact without modifying it.
    Inspect(InspectArgs),
    /// Harden an APK by injecting the runtime payload.
    Shield(Box<ShieldArgs>),
    /// Verify an output artifact and optionally write a report.
    Verify(VerifyArgs),
    /// Install and launch an APK on a connected Android device through ADB.
    RuntimeSmoke(RuntimeSmokeArgs),
    /// Build and sign a runtime payload pack from compiled Android artifacts.
    BuildPayloadPack(BuildPayloadPackArgs),
    /// Check host dependencies required by the Android pipeline.
    Doctor,
    /// Display CLI, payload, schema, and build version information.
    Version,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ShieldArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[arg(long, value_enum, default_value = "external")]
    signing_mode: SigningMode,
    #[arg(long)]
    keystore: Option<PathBuf>,
    #[arg(long)]
    keystore_alias: Option<String>,
    #[arg(long)]
    keystore_password_env: Option<String>,
    #[arg(long)]
    key_password_env: Option<String>,
    #[arg(long)]
    expected_cert_sha256: Option<String>,
    #[arg(long)]
    payload_pack: Option<PathBuf>,
    #[arg(long)]
    payload_signing_public_key_hex: Option<String>,
    #[arg(long)]
    signing_request: Option<PathBuf>,
    #[arg(long)]
    verification_template: Option<PathBuf>,
    #[arg(long)]
    keep_workdir: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    report: Option<PathBuf>,
    #[arg(long)]
    expected_cert_sha256: Option<String>,
}

#[derive(Debug, Args)]
struct RuntimeSmokeArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    package: Option<String>,
    #[arg(long)]
    activity: Option<String>,
    #[arg(long)]
    device_serial: Option<String>,
    #[arg(long, default_value_t = 1500)]
    wait_after_launch_ms: u64,
    #[arg(long)]
    no_uninstall: bool,
    #[arg(long)]
    report: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct BuildPayloadPackArgs {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    bootstrap_dex: PathBuf,
    #[arg(long = "native-lib", value_name = "ABI=PATH")]
    native_libs: Vec<String>,
    #[arg(long)]
    payload_version: String,
    #[arg(long)]
    payload_signing_key_env: String,
    #[arg(long)]
    minimum_cli_version: Option<String>,
    #[arg(long)]
    maximum_cli_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SigningMode {
    Local,
    External,
}

fn main() {
    let exit_code = match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {}", error.message());
            error.exit_code()
        }
    };

    std::process::exit(exit_code.code());
}

fn run() -> RaspResult<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => inspect(args),
        Commands::Shield(args) => shield(*args),
        Commands::Verify(args) => verify(args),
        Commands::RuntimeSmoke(args) => runtime_smoke(args),
        Commands::BuildPayloadPack(args) => build_payload_pack_command(args),
        Commands::Doctor => doctor(),
        Commands::Version => version(),
    }
}

fn inspect(args: InspectArgs) -> RaspResult<ExitCode> {
    let result = inspect_apk(&args.input)
        .map_err(|error| RaspError::new(error.exit_code(), error.to_string()))?;

    match args.format {
        OutputFormat::Text => {
            print_inspection_text(&result);
        }
        OutputFormat::Json => {
            let output = serde_json::to_string_pretty(&result).map_err(|error| {
                RaspError::new(
                    ExitCode::ArtifactInspectionFailure,
                    format!("failed to serialize inspection result: {error}"),
                )
            })?;
            write_or_print(args.output.as_ref(), &output)?;
        }
    }

    Ok(ExitCode::Success)
}

fn shield(args: ShieldArgs) -> RaspResult<ExitCode> {
    validate_signing_args(&args)?;
    validate_payload_pack_args(&args)?;

    let config = load_config(&args.config).map_err(|error| error.into_rasp_error())?;

    if !args.input.exists() {
        return Err(RaspError::new(
            ExitCode::ArtifactInspectionFailure,
            format!("input artifact does not exist: {}", args.input.display()),
        ));
    }
    validate_shield_output_path(&args.input, &args.output)?;

    let payload_pack_path = args
        .payload_pack
        .as_deref()
        .expect("payload pack is required by validate_payload_pack_args");
    let verification_key = PayloadVerificationKey::from_hex(
        args.payload_signing_public_key_hex
            .as_deref()
            .expect("payload signing key is required by validate_payload_pack_args"),
    )
    .map_err(|error| RaspError::new(ExitCode::PayloadSignatureFailure, error.to_string()))?;
    let payload_pack = load_payload_pack_verified(
        payload_pack_path,
        env!("CARGO_PKG_VERSION"),
        &verification_key,
    )
    .map_err(|error| RaspError::new(ExitCode::PayloadSignatureFailure, error.to_string()))?;
    let payload_files = PayloadFiles {
        bootstrap_dex_path: payload_pack.bootstrap_dex_path.clone(),
        abi_libraries: payload_pack.abi_libraries.clone(),
    };

    let input_artifact = artifact_descriptor(&args.input)?;
    let input_inspection = inspect_apk(&args.input).map_err(|error| {
        RaspError::new(
            error.exit_code(),
            format!("failed to inspect input APK before shielding: {error}"),
        )
    })?;
    let expected_certificate_sha256 =
        expected_certificate_digests(&config, args.expected_cert_sha256.as_deref())?;
    let rewrite_options = ApkRewriteOptions {
        build_id: input_artifact.sha256.clone(),
        provider_init_order: 1000,
        integrity_manifest: IntegrityManifestInput {
            application_profile: config.application.profile.clone(),
            build_environment: config.application.build_environment.clone(),
            expected_package_name: config.application.expected_package_name.clone(),
            policy_digest_sha256: sha256_json(&config)?,
            runtime_policy: integrity_runtime_policy(&config),
            expected_certificate_sha256: expected_certificate_sha256.clone(),
            payload_version: payload_pack.manifest.payload_version.clone(),
            payload_file_sha256: payload_file_digests(&payload_pack.manifest.files),
            protected_asset_paths: protected_asset_paths(&config, &input_inspection),
            generated_by: IntegrityTool {
                name: "rasp-cli".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        },
    };
    let rewrite_output_path = match args.signing_mode {
        SigningMode::External => args.output.clone(),
        SigningMode::Local => temporary_apk_path(&args.output, "unsigned"),
    };
    let rewrite_report = rewrite_unsigned_apk_with_payload(
        &args.input,
        &rewrite_output_path,
        &payload_files,
        &rewrite_options,
    )
    .map_err(apk_rewrite_error_into_rasp_error)?;
    let unsigned_artifact = artifact_descriptor(&rewrite_output_path)?;
    let payload_descriptor = PayloadDescriptor {
        version: payload_pack.manifest.payload_version.clone(),
        bootstrap_dex_entry: rewrite_report.inserted_dex_entry.clone(),
        native_library_entries: rewrite_report.inserted_native_library_entries.clone(),
    };

    match args.signing_mode {
        SigningMode::External => {
            let signing_request_path = args
                .signing_request
                .clone()
                .unwrap_or_else(|| sibling_json_path(&args.output, "signing-request"));
            let verification_template_path = args
                .verification_template
                .clone()
                .unwrap_or_else(|| sibling_json_path(&args.output, "verification-template"));

            let external_signing_request = ExternalSigningRequest::new(
                input_artifact,
                unsigned_artifact.clone(),
                payload_descriptor.clone(),
                ExternalSigningDetails {
                    expected_certificate_sha256: args
                        .expected_cert_sha256
                        .clone()
                        .expect("expected certificate is required by validate_signing_args"),
                    preserve_signature_lineage: config.android.preserve_signature_lineage,
                },
                ToolDescriptor {
                    name: "rasp-cli".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
            );
            let verification_template = VerificationTemplate::new(
                default_signed_apk_path(&args.output),
                unsigned_artifact,
                args.expected_cert_sha256
                    .clone()
                    .expect("expected certificate is required by validate_signing_args"),
                payload_descriptor,
            );
            write_json_file(&signing_request_path, &external_signing_request)?;
            write_json_file(&verification_template_path, &verification_template)?;

            println!("unsigned_apk: {}", rewrite_report.output_path.display());
            println!("signing_request: {}", signing_request_path.display());
            println!(
                "verification_template: {}",
                verification_template_path.display()
            );
        }
        SigningMode::Local => {
            let aligned_apk_path = temporary_apk_path(&args.output, "aligned");
            let signing_tools = AndroidSigningTools::default();
            align_apk(&signing_tools, &rewrite_output_path, &aligned_apk_path).map_err(
                |error| signing_tool_error_into_rasp_error(error, ExitCode::AlignmentFailure),
            )?;
            verify_alignment(&signing_tools, &aligned_apk_path).map_err(|error| {
                signing_tool_error_into_rasp_error(error, ExitCode::AlignmentFailure)
            })?;
            let sign_options = apk_sign_options_from_args(&args)?;
            sign_apk(
                &signing_tools,
                &aligned_apk_path,
                &args.output,
                &sign_options,
            )
            .map_err(|error| signing_tool_error_into_rasp_error(error, ExitCode::SigningFailure))?;
            verify_apk_signature(&signing_tools, &args.output).map_err(|error| {
                signing_tool_error_into_rasp_error(error, ExitCode::SigningFailure)
            })?;
            verify_signed_certificate_after_local_signing(
                &args.output,
                &expected_certificate_sha256,
            )?;

            println!("signed_apk: {}", args.output.display());
            if args.keep_workdir {
                println!("unsigned_apk: {}", rewrite_output_path.display());
                println!("aligned_unsigned_apk: {}", aligned_apk_path.display());
            } else {
                cleanup_temporary_file(&rewrite_output_path)?;
                cleanup_temporary_file(&aligned_apk_path)?;
            }
        }
    }
    println!("payload_version: {}", payload_pack.manifest.payload_version);
    println!(
        "inserted_provider: {} ({})",
        rewrite_report.inserted_manifest_provider.name,
        rewrite_report.inserted_manifest_provider.authorities
    );
    println!(
        "inserted_integrity_manifest: {}",
        rewrite_report.inserted_integrity_manifest_entry
    );
    println!("inserted_dex: {}", rewrite_report.inserted_dex_entry);
    println!(
        "inserted_native_libraries: {}",
        rewrite_report.inserted_native_library_entries.join(", ")
    );
    println!(
        "removed_signature_entries: {}",
        if rewrite_report.skipped_signature_entries.is_empty() {
            "none".to_string()
        } else {
            rewrite_report.skipped_signature_entries.join(", ")
        }
    );

    Ok(ExitCode::Success)
}

fn verify(args: VerifyArgs) -> RaspResult<ExitCode> {
    if let Some(expected_cert_sha256) = args.expected_cert_sha256.as_deref() {
        if expected_cert_sha256.is_empty() {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                "--expected-cert-sha256 must not be empty",
            ));
        }
        if !is_hex_sha256(expected_cert_sha256) {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                "--expected-cert-sha256 must be a 64-character SHA-256 hex digest",
            ));
        }
    }

    if !args.input.exists() {
        return Err(RaspError::new(
            ExitCode::VerificationFailure,
            format!("input artifact does not exist: {}", args.input.display()),
        ));
    }

    let input_artifact = artifact_descriptor(&args.input)?;
    let inspection = match inspect_apk(&args.input) {
        Ok(inspection) => inspection,
        Err(error) => {
            let mut checks = BTreeMap::new();
            checks.insert("apk_inspection".to_string(), format!("FAIL: {error}"));
            let report = VerificationReport {
                schema_version: VERIFICATION_REPORT_SCHEMA_VERSION,
                result: VerificationResult::Fail,
                input: Some(input_artifact),
                application: None,
                payload: None,
                signing: None,
                checks,
                warnings: Vec::new(),
            };
            write_verification_report(args.report.as_ref(), &report)?;
            return Err(RaspError::new(
                ExitCode::VerificationFailure,
                error.to_string(),
            ));
        }
    };

    let mut checks = BTreeMap::new();
    let mut failures = Vec::new();
    let mut warnings = inspection.warnings.clone();
    warnings.extend(inspection.compatibility_warnings.clone());
    record_check(
        &mut checks,
        &mut failures,
        "apk_inspection",
        true,
        "APK inspection completed",
    );
    record_check(
        &mut checks,
        &mut failures,
        "zip_safety",
        inspection.apk_compression.duplicate_paths.is_empty()
            && inspection.apk_compression.zip_slip_paths.is_empty(),
        "ZIP contains no duplicate or unsafe paths",
    );

    let integrity_manifest = match read_integrity_manifest(&args.input) {
        Ok(manifest) => {
            record_check(
                &mut checks,
                &mut failures,
                "integrity_manifest",
                true,
                "internal integrity manifest is present and parseable",
            );
            Some(manifest)
        }
        Err(error) => {
            record_check(
                &mut checks,
                &mut failures,
                "integrity_manifest",
                false,
                error,
            );
            None
        }
    };

    if let Some(manifest) = integrity_manifest.as_ref() {
        verify_application_metadata(manifest, &inspection, &mut checks, &mut failures);
        verify_provider(manifest, &inspection, &mut checks, &mut failures);
        verify_protected_assets(
            manifest,
            &args.input,
            &inspection,
            &mut checks,
            &mut failures,
        );
        verify_apk_inventory(manifest, &args.input, &mut checks, &mut failures);
    }

    let signing = verify_signing(
        args.expected_cert_sha256.as_deref(),
        &inspection,
        &mut checks,
        &mut failures,
        &mut warnings,
    );
    let application = integrity_manifest
        .as_ref()
        .map(|manifest| VerificationApplication {
            package_name: inspection.package_name.clone(),
            provider_name: Some(manifest.provider.name.clone()),
            provider_authorities: Some(manifest.provider.authorities.clone()),
        });
    let payload = integrity_manifest
        .as_ref()
        .map(|manifest| VerificationPayload {
            integrity_manifest_entry: INTEGRITY_MANIFEST_ENTRY.to_string(),
            protected_assets: manifest
                .protected_assets
                .iter()
                .map(|asset| asset.path.clone())
                .collect(),
        });

    let result = if failures.is_empty() {
        VerificationResult::Pass
    } else {
        VerificationResult::Fail
    };
    let report = VerificationReport {
        schema_version: VERIFICATION_REPORT_SCHEMA_VERSION,
        result,
        input: Some(input_artifact),
        application,
        payload,
        signing: Some(signing),
        checks,
        warnings,
    };
    write_verification_report(args.report.as_ref(), &report)?;

    if result == VerificationResult::Pass {
        Ok(ExitCode::Success)
    } else {
        Err(RaspError::new(
            ExitCode::VerificationFailure,
            format!("verification failed: {}", failures.join("; ")),
        ))
    }
}

fn runtime_smoke(args: RuntimeSmokeArgs) -> RaspResult<ExitCode> {
    if !args.input.exists() {
        return Err(RaspError::new(
            ExitCode::RuntimeSmokeTestFailure,
            format!("input APK does not exist: {}", args.input.display()),
        ));
    }

    let inspection = inspect_apk(&args.input).map_err(|error| {
        RaspError::new(
            ExitCode::RuntimeSmokeTestFailure,
            format!("failed to inspect APK before runtime smoke test: {error}"),
        )
    })?;
    let package_name = resolve_smoke_package(&args, &inspection)?;
    let launch_activity = args.activity.clone().or(inspection.main_activity.clone());
    let mut plan = RuntimeSmokeTestPlan::new(&args.input, package_name);
    plan.launch_activity = launch_activity;
    plan.device_serial = args.device_serial.clone();
    plan.uninstall_after_test = !args.no_uninstall;
    plan.wait_after_launch_ms = args.wait_after_launch_ms;

    let report = run_runtime_smoke_test(&AdbTool::default(), &plan)
        .map_err(runtime_smoke_error_into_rasp_error)?;
    write_runtime_smoke_report(args.report.as_ref(), &report)?;
    print_runtime_smoke_summary(&report);

    if report.result == RuntimeSmokeTestResult::Pass {
        Ok(ExitCode::Success)
    } else {
        Err(RaspError::new(
            ExitCode::RuntimeSmokeTestFailure,
            "runtime smoke test failed",
        ))
    }
}

fn build_payload_pack_command(args: BuildPayloadPackArgs) -> RaspResult<ExitCode> {
    validate_payload_build_args(&args)?;

    let signing_key_hex = std::env::var(&args.payload_signing_key_env).map_err(|error| {
        RaspError::new(
            ExitCode::InvalidCliArguments,
            format!(
                "failed to read payload signing key from {}: {error}",
                args.payload_signing_key_env
            ),
        )
    })?;
    let signing_key = PayloadSigningKey::from_hex(signing_key_hex.trim())
        .map_err(payload_build_error_into_rasp_error)?;
    let abi_libraries = parse_native_library_args(&args.native_libs)?;
    let minimum_cli_version = args
        .minimum_cli_version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let maximum_cli_version = args
        .maximum_cli_version
        .clone()
        .unwrap_or_else(default_payload_maximum_cli_version);

    let report = build_payload_pack(
        &PayloadPackBuildOptions {
            output_root: args.output.clone(),
            bootstrap_dex_path: args.bootstrap_dex.clone(),
            abi_libraries,
            payload_version: args.payload_version.clone(),
            minimum_cli_version,
            maximum_cli_version,
        },
        &signing_key,
    )
    .map_err(payload_build_error_into_rasp_error)?;

    let verification_key = PayloadVerificationKey::from_hex(&report.payload_signing_public_key_hex)
        .map_err(payload_build_error_into_rasp_error)?;
    load_payload_pack_verified(&report.root, env!("CARGO_PKG_VERSION"), &verification_key)
        .map_err(payload_build_error_into_rasp_error)?;

    println!("payload_pack: {}", report.root.display());
    println!("manifest: {}", report.manifest_path.display());
    println!("signature: {}", report.signature_path.display());
    println!("payload_version: {}", report.payload_version);
    println!("supported_abis: {}", report.supported_abis.join(", "));
    println!(
        "payload_signing_public_key_hex: {}",
        report.payload_signing_public_key_hex
    );

    Ok(ExitCode::Success)
}

fn validate_payload_build_args(args: &BuildPayloadPackArgs) -> RaspResult<()> {
    if args.output.as_os_str().is_empty() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--output must not be empty",
        ));
    }
    if args.output.is_file() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            format!(
                "--output must be a directory path: {}",
                args.output.display()
            ),
        ));
    }
    if args.payload_version.trim().is_empty() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--payload-version must not be empty",
        ));
    }
    if args.native_libs.is_empty() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "at least one --native-lib ABI=PATH entry is required",
        ));
    }
    if !is_valid_env_var_name(&args.payload_signing_key_env) {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--payload-signing-key-env must be an environment-variable name, not a value",
        ));
    }

    Ok(())
}

fn parse_native_library_args(values: &[String]) -> RaspResult<BTreeMap<String, PathBuf>> {
    let mut abi_libraries = BTreeMap::new();
    for value in values {
        let Some((abi, path)) = value.split_once('=') else {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                format!("--native-lib must use ABI=PATH syntax, got {value}"),
            ));
        };
        if !is_supported_payload_abi(abi) {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                format!("unsupported payload ABI: {abi}"),
            ));
        }
        if path.is_empty() {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                format!("native library path for {abi} must not be empty"),
            ));
        }
        if abi_libraries
            .insert(abi.to_string(), PathBuf::from(path))
            .is_some()
        {
            return Err(RaspError::new(
                ExitCode::InvalidCliArguments,
                format!("duplicate --native-lib entry for ABI {abi}"),
            ));
        }
    }

    Ok(abi_libraries)
}

fn is_supported_payload_abi(abi: &str) -> bool {
    matches!(abi, "arm64-v8a" | "armeabi-v7a" | "x86_64")
}

fn default_payload_maximum_cli_version() -> String {
    let major = env!("CARGO_PKG_VERSION")
        .split('.')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("0");
    format!("{major}.x")
}

fn payload_build_error_into_rasp_error(error: PayloadPackError) -> RaspError {
    let exit_code = match error {
        PayloadPackError::InvalidSigningKey(_)
        | PayloadPackError::InvalidPublicKey(_)
        | PayloadPackError::Validation(_) => ExitCode::InvalidCliArguments,
        PayloadPackError::InvalidSignature(_) | PayloadPackError::DigestMismatch { .. } => {
            ExitCode::PayloadSignatureFailure
        }
        PayloadPackError::Io(_) | PayloadPackError::Json(_) => ExitCode::GeneralProcessingFailure,
    };
    RaspError::new(exit_code, error.to_string())
}

fn resolve_smoke_package(
    args: &RuntimeSmokeArgs,
    inspection: &InspectionResult,
) -> RaspResult<String> {
    match (args.package.as_deref(), inspection.package_name.as_deref()) {
        (Some(explicit), Some(inspected)) if explicit != inspected => Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            format!("--package {explicit} does not match APK package {inspected}"),
        )),
        (Some(explicit), _) if explicit.trim().is_empty() => Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--package must not be empty",
        )),
        (Some(explicit), _) => Ok(explicit.to_string()),
        (None, Some(inspected)) => Ok(inspected.to_string()),
        (None, None) => Err(RaspError::new(
            ExitCode::RuntimeSmokeTestFailure,
            "package name could not be decoded from APK; pass --package",
        )),
    }
}

fn runtime_smoke_error_into_rasp_error(error: RuntimeSmokeError) -> RaspError {
    let exit_code = match error {
        RuntimeSmokeError::Io(_) => ExitCode::MissingExternalDependency,
        RuntimeSmokeError::Validation(_) => ExitCode::RuntimeSmokeTestFailure,
    };
    RaspError::new(exit_code, error.to_string())
}

fn write_runtime_smoke_report(
    path: Option<&PathBuf>,
    report: &RuntimeSmokeTestReport,
) -> RaspResult<()> {
    if let Some(path) = path {
        write_json_file(path, report)?;
    }
    Ok(())
}

fn print_runtime_smoke_summary(report: &RuntimeSmokeTestReport) {
    println!(
        "runtime_smoke_result: {}",
        match report.result {
            RuntimeSmokeTestResult::Pass => "PASS",
            RuntimeSmokeTestResult::Fail => "FAIL",
        }
    );
    println!("package_name: {}", report.package_name);
    println!(
        "device_serial: {}",
        report.device_serial.as_deref().unwrap_or("default")
    );
    for step in &report.steps {
        println!(
            "{}: {} - {}",
            step.name,
            format!("{:?}", step.result).to_ascii_uppercase(),
            step.detail
        );
    }
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

fn record_check(
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
    name: &str,
    passed: bool,
    message: impl Into<String>,
) {
    let message = message.into();
    if passed {
        checks.insert(name.to_string(), format!("PASS: {message}"));
    } else {
        checks.insert(name.to_string(), format!("FAIL: {message}"));
        failures.push(format!("{name}: {message}"));
    }
}

fn read_integrity_manifest(path: &Path) -> Result<IntegrityManifest, String> {
    let bytes = read_zip_entry(path, INTEGRITY_MANIFEST_ENTRY)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!("failed to parse {INTEGRITY_MANIFEST_ENTRY} as integrity manifest JSON: {error}")
    })
}

fn verify_application_metadata(
    manifest: &IntegrityManifest,
    inspection: &InspectionResult,
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    let actual_package = inspection.package_name.as_deref();
    let package_matches_manifest = actual_package == Some(manifest.package_name.as_str());
    let package_matches_expected =
        manifest.package_name == manifest.application.expected_package_name;
    record_check(
        checks,
        failures,
        "application_metadata",
        package_matches_manifest && package_matches_expected,
        if package_matches_manifest && package_matches_expected {
            format!(
                "package {} matches integrity manifest",
                manifest.package_name
            )
        } else {
            format!(
                "APK package {:?}, integrity package {}, expected package {}",
                actual_package, manifest.package_name, manifest.application.expected_package_name
            )
        },
    );
}

fn verify_provider(
    manifest: &IntegrityManifest,
    inspection: &InspectionResult,
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    let provider_found = inspection.content_providers.iter().any(|provider| {
        provider.name.as_deref() == Some(manifest.provider.name.as_str())
            && provider.authorities.as_deref() == Some(manifest.provider.authorities.as_str())
            && provider.exported == Some(false)
    });
    record_check(
        checks,
        failures,
        "bootstrap_provider",
        provider_found && !manifest.provider.exported,
        if provider_found && !manifest.provider.exported {
            format!(
                "provider {} ({}) is present and not exported",
                manifest.provider.name, manifest.provider.authorities
            )
        } else {
            format!(
                "provider {} ({}) was not found with exported=false",
                manifest.provider.name, manifest.provider.authorities
            )
        },
    );
}

fn verify_protected_assets(
    manifest: &IntegrityManifest,
    input: &Path,
    inspection: &InspectionResult,
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    let mut digest_failures = Vec::new();
    let mut bootstrap_failures = Vec::new();
    let mut native_failures = Vec::new();
    let mut flutter_failures = Vec::new();
    let mut payload_digest_failures = Vec::new();
    let mut has_bootstrap = false;
    let mut native_count = 0usize;
    let mut flutter_asset_count = 0usize;

    for asset in &manifest.protected_assets {
        match zip_entry_sha256(input, &asset.path) {
            Ok(actual) if actual.eq_ignore_ascii_case(&asset.sha256) => {}
            Ok(actual) => digest_failures.push(format!(
                "{} expected {}, got {}",
                asset.path, asset.sha256, actual
            )),
            Err(error) => digest_failures.push(error),
        }

        match &asset.kind {
            IntegrityProtectedAssetKind::BootstrapDex => {
                has_bootstrap = true;
                if !inspection
                    .dex_files
                    .iter()
                    .any(|dex_file| dex_file.path == asset.path)
                {
                    bootstrap_failures.push(format!(
                        "{} is not present in the APK DEX inventory",
                        asset.path
                    ));
                }
                if !manifest
                    .payload
                    .files
                    .values()
                    .any(|digest| digest.eq_ignore_ascii_case(&asset.sha256))
                {
                    payload_digest_failures.push(format!(
                        "{} digest is not declared in payload.files",
                        asset.path
                    ));
                }
            }
            IntegrityProtectedAssetKind::NativeLibrary => {
                native_count += 1;
                if !inspection
                    .native_libraries
                    .iter()
                    .any(|library| library.path == asset.path)
                {
                    native_failures.push(format!(
                        "{} is not present in the APK native library inventory",
                        asset.path
                    ));
                }
                if !manifest
                    .payload
                    .files
                    .values()
                    .any(|digest| digest.eq_ignore_ascii_case(&asset.sha256))
                {
                    payload_digest_failures.push(format!(
                        "{} digest is not declared in payload.files",
                        asset.path
                    ));
                }
            }
            IntegrityProtectedAssetKind::JavascriptBundle => {}
            IntegrityProtectedAssetKind::FlutterAsset => {
                flutter_asset_count += 1;
            }
            IntegrityProtectedAssetKind::FlutterNativeLibrary => {
                flutter_asset_count += 1;
                if !inspection
                    .native_libraries
                    .iter()
                    .any(|library| library.path == asset.path)
                {
                    flutter_failures.push(format!(
                        "{} is not present in the APK native library inventory",
                        asset.path
                    ));
                }
            }
        }
    }

    if !has_bootstrap {
        bootstrap_failures.push("no BOOTSTRAP_DEX protected asset is declared".to_string());
    }
    if native_count == 0 {
        native_failures.push("no NATIVE_LIBRARY protected asset is declared".to_string());
    }

    record_check(
        checks,
        failures,
        "protected_asset_digests",
        digest_failures.is_empty(),
        if digest_failures.is_empty() {
            "all protected asset digests match APK entries".to_string()
        } else {
            digest_failures.join("; ")
        },
    );
    record_check(
        checks,
        failures,
        "bootstrap_dex",
        bootstrap_failures.is_empty(),
        if bootstrap_failures.is_empty() {
            "bootstrap DEX is declared and present".to_string()
        } else {
            bootstrap_failures.join("; ")
        },
    );
    record_check(
        checks,
        failures,
        "native_payload_libraries",
        native_failures.is_empty(),
        if native_failures.is_empty() {
            "native payload libraries are declared and present".to_string()
        } else {
            native_failures.join("; ")
        },
    );
    record_check(
        checks,
        failures,
        "payload_digest_manifest",
        payload_digest_failures.is_empty(),
        if payload_digest_failures.is_empty() {
            "protected payload asset digests are declared in payload.files".to_string()
        } else {
            payload_digest_failures.join("; ")
        },
    );
    if flutter_asset_count > 0 {
        record_check(
            checks,
            failures,
            "flutter_protected_assets",
            flutter_failures.is_empty(),
            if flutter_failures.is_empty() {
                format!("{flutter_asset_count} Flutter protected assets are declared and present")
            } else {
                flutter_failures.join("; ")
            },
        );
    }
}

fn verify_apk_inventory(
    manifest: &IntegrityManifest,
    input: &Path,
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    if manifest.apk_inventory.entry_count == 0
        && manifest.apk_inventory.entry_set_sha256.is_empty()
        && manifest.apk_inventory.executable_entry_count == 0
        && manifest
            .apk_inventory
            .executable_entry_set_sha256
            .is_empty()
    {
        checks.insert(
            "apk_inventory".to_string(),
            "SKIP: APK inventory is not declared in this integrity manifest".to_string(),
        );
        return;
    }

    let actual = match apk_inventory_from_zip(input) {
        Ok(actual) => actual,
        Err(error) => {
            record_check(checks, failures, "apk_inventory", false, error);
            return;
        }
    };

    let expected = &manifest.apk_inventory;
    let inventory_matches = actual.entry_count == expected.entry_count
        && actual
            .entry_set_sha256
            .eq_ignore_ascii_case(&expected.entry_set_sha256)
        && actual.executable_entry_count == expected.executable_entry_count
        && actual
            .executable_entry_set_sha256
            .eq_ignore_ascii_case(&expected.executable_entry_set_sha256);

    record_check(
        checks,
        failures,
        "apk_inventory",
        inventory_matches,
        if inventory_matches {
            format!(
                "{} non-signature entries and {} executable entries match the integrity manifest",
                actual.entry_count, actual.executable_entry_count
            )
        } else {
            format!(
                "expected entries {} / executable {} with digests {} / {}, got entries {} / executable {} with digests {} / {}",
                expected.entry_count,
                expected.executable_entry_count,
                expected.entry_set_sha256,
                expected.executable_entry_set_sha256,
                actual.entry_count,
                actual.executable_entry_count,
                actual.entry_set_sha256,
                actual.executable_entry_set_sha256
            )
        },
    );
}

fn verify_signing(
    expected_cert_sha256: Option<&str>,
    inspection: &InspectionResult,
    checks: &mut BTreeMap<String, String>,
    failures: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> VerificationSigning {
    let expected = expected_cert_sha256.map(str::to_ascii_lowercase);
    let matched = expected.as_ref().and_then(|expected| {
        inspection
            .signature_certificates
            .iter()
            .find(|certificate| certificate.sha256.eq_ignore_ascii_case(expected))
            .map(|certificate| certificate.sha256.clone())
    });

    match expected.as_ref() {
        Some(expected) => record_check(
            checks,
            failures,
            "signing_certificate",
            matched.is_some(),
            if matched.is_some() {
                format!("signing certificate matches {expected}")
            } else {
                format!("signing certificate {expected} was not found")
            },
        ),
        None => {
            checks.insert(
                "signing_certificate".to_string(),
                "SKIP: --expected-cert-sha256 was not provided".to_string(),
            );
            warnings.push("signing certificate check skipped".to_string());
        }
    }

    VerificationSigning {
        expected_certificate_sha256: expected,
        matched_certificate_sha256: matched,
        detected_signature_schemes: inspection
            .detected_signature_schemes
            .iter()
            .map(|scheme| signature_scheme_label(*scheme).to_string())
            .collect(),
    }
}

fn read_zip_entry(path: &Path, entry_name: &str) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("failed to read APK ZIP: {error}"))?;
    let mut entry = archive
        .by_name(entry_name)
        .map_err(|error| format!("APK is missing {entry_name}: {error}"))?;
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {entry_name}: {error}"))?;
    Ok(bytes)
}

fn zip_entry_sha256(path: &Path, entry_name: &str) -> Result<String, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("failed to read APK ZIP: {error}"))?;
    let mut entry = archive
        .by_name(entry_name)
        .map_err(|error| format!("APK is missing {entry_name}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = entry
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {entry_name}: {error}"))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex_lower(&hasher.finalize()))
}

fn apk_inventory_from_zip(path: &Path) -> Result<IntegrityApkInventory, String> {
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("failed to read APK ZIP: {error}"))?;
    let mut entries = BTreeSet::new();

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to read APK ZIP entry {index}: {error}"))?;
        let entry_name = entry.name().to_string();
        if entry.is_dir() || is_jar_signature_metadata_entry(&entry_name) {
            continue;
        }
        entries.insert(entry_name);
    }

    let executable_entries = entries
        .iter()
        .filter(|entry| is_executable_inventory_entry(entry))
        .cloned()
        .collect::<BTreeSet<_>>();

    Ok(IntegrityApkInventory {
        entry_count: entries.len(),
        entry_set_sha256: path_set_digest(&entries),
        executable_entry_count: executable_entries.len(),
        executable_entry_set_sha256: path_set_digest(&executable_entries),
    })
}

fn path_set_digest(paths: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(path.as_bytes());
        hasher.update([0]);
    }
    hex_lower(&hasher.finalize())
}

fn is_executable_inventory_entry(path: &str) -> bool {
    is_dex_entry_path(path)
        || is_native_library_entry_path(path)
        || path.ends_with(".dex")
        || path.ends_with(".jar")
        || path.ends_with(".apk")
        || path.ends_with(".so")
}

fn is_dex_entry_path(path: &str) -> bool {
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

fn is_jar_signature_metadata_entry(path: &str) -> bool {
    let upper = path.to_ascii_uppercase();
    upper == "META-INF/MANIFEST.MF"
        || upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA")
                || upper.ends_with(".DSA")
                || upper.ends_with(".EC")
                || upper.ends_with(".SF"))
}

fn write_verification_report(
    path: Option<&PathBuf>,
    report: &VerificationReport,
) -> RaspResult<()> {
    let body = serde_json::to_string_pretty(report).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to serialize verification report: {error}"),
        )
    })?;
    write_or_print(path, &body)
}

fn signature_scheme_label(scheme: ApkSignatureScheme) -> &'static str {
    match scheme {
        ApkSignatureScheme::V1Jar => "V1_JAR",
        ApkSignatureScheme::V2 => "V2",
        ApkSignatureScheme::V3 => "V3",
    }
}

fn doctor() -> RaspResult<ExitCode> {
    let signing_tools = AndroidSigningTools::default();
    let checks = vec![
        doctor_command("Java runtime", "java", &["-version"], true),
        doctor_zipalign(&signing_tools.zipalign),
        doctor_command_path("apksigner", &signing_tools.apksigner, &["--version"], true),
        doctor_command("Android Debug Bridge", "adb", &["version"], false),
        doctor_temp_dir(),
        doctor_host_arch(),
    ];

    let mut has_required_failure = false;
    for check in &checks {
        println!(
            "{}: {}{}",
            check.name,
            if check.passed { "PASS" } else { "FAIL" },
            check
                .detail
                .as_deref()
                .map(|detail| format!(" - {detail}"))
                .unwrap_or_default()
        );
        if check.required && !check.passed {
            has_required_failure = true;
        }
    }

    if has_required_failure {
        Err(RaspError::new(
            ExitCode::MissingExternalDependency,
            "one or more required host dependencies are missing",
        ))
    } else {
        Ok(ExitCode::Success)
    }
}

fn version() -> RaspResult<ExitCode> {
    println!("cli_version: {}", env!("CARGO_PKG_VERSION"));
    println!("payload_version: unavailable");
    println!("configuration_schema_version: {CONFIG_SCHEMA_VERSION}");
    println!("android_build_tools_version: unavailable");
    println!(
        "rust_build_target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "git_commit: {}",
        option_env!("GIT_COMMIT").unwrap_or("unknown")
    );
    Ok(ExitCode::Success)
}

fn validate_signing_args(args: &ShieldArgs) -> RaspResult<()> {
    match args.signing_mode {
        SigningMode::Local => {
            if args.keystore.is_none() {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "--keystore is required for local signing",
                ));
            }
            if args.keystore_alias.is_none() {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "--keystore-alias is required for local signing",
                ));
            }
            if args.keystore_password_env.is_none() {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "--keystore-password-env is required for local signing",
                ));
            }
            validate_optional_env_name(
                "--keystore-password-env",
                args.keystore_password_env.as_deref(),
            )?;
            validate_optional_env_name("--key-password-env", args.key_password_env.as_deref())?;
            if let Some(keystore) = args.keystore.as_ref() {
                if !keystore.is_file() {
                    return Err(RaspError::new(
                        ExitCode::InvalidCliArguments,
                        format!(
                            "--keystore must be an existing file: {}",
                            keystore.display()
                        ),
                    ));
                }
            }
            if let Some(expected_cert_sha256) = args.expected_cert_sha256.as_deref() {
                if !is_hex_sha256(expected_cert_sha256) {
                    return Err(RaspError::new(
                        ExitCode::InvalidCliArguments,
                        "--expected-cert-sha256 must be a 64-character SHA-256 hex digest",
                    ));
                }
            }
        }
        SigningMode::External => {
            let expected_cert_sha256 = args.expected_cert_sha256.as_deref().unwrap_or_default();
            if expected_cert_sha256.is_empty() {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "--expected-cert-sha256 is required for external signing",
                ));
            }
            if !is_hex_sha256(expected_cert_sha256) {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "--expected-cert-sha256 must be a 64-character SHA-256 hex digest",
                ));
            }
        }
    }

    Ok(())
}

fn validate_payload_pack_args(args: &ShieldArgs) -> RaspResult<()> {
    match (
        args.payload_pack.is_some(),
        args.payload_signing_public_key_hex.is_some(),
    ) {
        (true, true) => Ok(()),
        (true, false) => Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--payload-signing-public-key-hex is required when --payload-pack is provided",
        )),
        (false, true) => Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--payload-signing-public-key-hex requires --payload-pack",
        )),
        (false, false) => Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--payload-pack is required until bundled payloads are implemented",
        )),
    }
}

fn apk_rewrite_error_into_rasp_error(error: ApkRewriteError) -> RaspError {
    let exit_code = match error {
        ApkRewriteError::Validation(_)
        | ApkRewriteError::Manifest(_)
        | ApkRewriteError::Json(_) => ExitCode::PayloadInjectionFailure,
        ApkRewriteError::Io(_) | ApkRewriteError::Zip(_) | ApkRewriteError::UnsafeZip(_) => {
            ExitCode::PackageReconstructionFailure
        }
    };
    RaspError::new(exit_code, error.to_string())
}

fn signing_tool_error_into_rasp_error(
    error: SigningToolError,
    failure_code: ExitCode,
) -> RaspError {
    let exit_code = match &error {
        SigningToolError::Io { .. } => ExitCode::MissingExternalDependency,
        SigningToolError::Failed { .. } => failure_code,
    };
    RaspError::new(exit_code, error.to_string())
}

fn validate_shield_output_path(input: &Path, output: &Path) -> RaspResult<()> {
    if output.as_os_str().is_empty() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--output must not be empty",
        ));
    }
    if input == output {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--input and --output must be different paths",
        ));
    }
    if output.exists() && fs::canonicalize(input).ok() == fs::canonicalize(output).ok() {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            "--input and --output must be different paths",
        ));
    }
    Ok(())
}

fn apk_sign_options_from_args(args: &ShieldArgs) -> RaspResult<ApkSignOptions> {
    Ok(ApkSignOptions {
        keystore_path: args
            .keystore
            .clone()
            .expect("keystore is required by validate_signing_args"),
        key_alias: args
            .keystore_alias
            .clone()
            .expect("keystore alias is required by validate_signing_args"),
        keystore_password_env: args.keystore_password_env.clone(),
        key_password_env: args.key_password_env.clone(),
    })
}

fn verify_signed_certificate_after_local_signing(
    signed_apk: &Path,
    expected_certificate_sha256: &[String],
) -> RaspResult<()> {
    let inspection = inspect_apk(signed_apk).map_err(|error| {
        RaspError::new(
            ExitCode::SigningFailure,
            format!("failed to inspect signed APK certificate: {error}"),
        )
    })?;
    if inspection.signature_certificates.is_empty() {
        return Err(RaspError::new(
            ExitCode::SigningFailure,
            "apksigner completed, but no signing certificates were decoded from the signed APK",
        ));
    }
    if !expected_certificate_sha256.is_empty()
        && !inspection.signature_certificates.iter().any(|certificate| {
            expected_certificate_sha256
                .iter()
                .any(|expected| certificate.sha256.eq_ignore_ascii_case(expected))
        })
    {
        return Err(RaspError::new(
            ExitCode::SigningFailure,
            "signed APK certificate does not match any expected certificate digest",
        ));
    }
    Ok(())
}

fn temporary_apk_path(output: &Path, label: &str) -> PathBuf {
    let file_name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output.apk");
    output.with_file_name(format!(".{file_name}.{label}-{}", std::process::id()))
}

fn cleanup_temporary_file(path: &Path) -> RaspResult<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            RaspError::new(
                ExitCode::GeneralProcessingFailure,
                format!(
                    "failed to remove temporary file {}: {error}",
                    path.display()
                ),
            )
        })?;
    }
    Ok(())
}

fn expected_certificate_digests(
    config: &RaspConfig,
    signing_expected_cert_sha256: Option<&str>,
) -> RaspResult<Vec<String>> {
    let mut digests = Vec::with_capacity(config.android.certificate_sha256.len());
    for digest in &config.android.certificate_sha256 {
        if digest == "CURRENT_SIGNING_CERTIFICATE_SHA256" {
            let Some(expected_digest) = signing_expected_cert_sha256 else {
                return Err(RaspError::new(
                    ExitCode::InvalidCliArguments,
                    "CURRENT_SIGNING_CERTIFICATE_SHA256 requires --expected-cert-sha256",
                ));
            };
            digests.push(expected_digest.to_ascii_lowercase());
        } else {
            digests.push(digest.to_ascii_lowercase());
        }
    }
    Ok(digests)
}

fn integrity_runtime_policy(config: &RaspConfig) -> IntegrityRuntimePolicy {
    IntegrityRuntimePolicy {
        thresholds: IntegrityRiskThresholds {
            report: config.risk_policy.thresholds.report,
            warn: config.risk_policy.thresholds.warn,
            restrict: config.risk_policy.thresholds.restrict,
            terminate: config.risk_policy.thresholds.terminate,
        },
        runtime_high_risk_action: integrity_risk_action(config.risk_policy.runtime_high_risk),
        startup_integrity_action: integrity_risk_action(
            config.risk_policy.startup_signature_mismatch,
        ),
        startup_payload_tampering_action: integrity_risk_action(
            config.risk_policy.startup_payload_tampering,
        ),
        monitoring: IntegrityRuntimeMonitoring {
            enabled: config.runtime.monitoring_enabled,
            scan_interval_minimum_ms: config.runtime.scan_interval_ms.minimum,
            scan_interval_maximum_ms: config.runtime.scan_interval_ms.maximum,
            deep_scan_on_suspicion: config.runtime.deep_scan_on_suspicion,
            monitor_background_state: config.runtime.monitor_background_state,
        },
    }
}

fn integrity_risk_action(action: RiskAction) -> IntegrityRiskAction {
    match action {
        RiskAction::Allow => IntegrityRiskAction::Allow,
        RiskAction::Report => IntegrityRiskAction::Report,
        RiskAction::Warn => IntegrityRiskAction::Warn,
        RiskAction::LockStartup => IntegrityRiskAction::LockStartup,
        RiskAction::Terminate => IntegrityRiskAction::Terminate,
    }
}

fn protected_asset_paths(
    config: &RaspConfig,
    inspection: &InspectionResult,
) -> BTreeMap<String, IntegrityProtectedAssetKind> {
    let mut paths = BTreeMap::new();
    if config.protections.javascript_bundle_integrity.enabled {
        paths.extend(
            config
                .protections
                .javascript_bundle_integrity
                .paths
                .iter()
                .filter(|path| !path.trim().is_empty())
                .map(|path| (path.clone(), IntegrityProtectedAssetKind::JavascriptBundle)),
        );
    }

    if config.protections.flutter_integrity.enabled {
        let configured_flutter_paths = &config.protections.flutter_integrity.paths;
        if configured_flutter_paths.is_empty() {
            if let Some(flutter) = inspection.flutter.as_ref() {
                paths.extend(flutter.app_libraries.iter().map(|path| {
                    (
                        path.clone(),
                        IntegrityProtectedAssetKind::FlutterNativeLibrary,
                    )
                }));
                paths.extend(flutter.engine_libraries.iter().map(|path| {
                    (
                        path.clone(),
                        IntegrityProtectedAssetKind::FlutterNativeLibrary,
                    )
                }));
                paths.extend(
                    flutter
                        .asset_entries
                        .iter()
                        .map(|path| (path.clone(), IntegrityProtectedAssetKind::FlutterAsset)),
                );
            }
        } else {
            paths.extend(
                configured_flutter_paths
                    .iter()
                    .filter(|path| !path.trim().is_empty())
                    .map(|path| (path.clone(), flutter_protected_asset_kind(path))),
            );
        }
    }

    paths
}

fn flutter_protected_asset_kind(path: &str) -> IntegrityProtectedAssetKind {
    if is_native_library_entry_path(path) {
        IntegrityProtectedAssetKind::FlutterNativeLibrary
    } else {
        IntegrityProtectedAssetKind::FlutterAsset
    }
}

fn is_native_library_entry_path(path: &str) -> bool {
    let mut parts = path.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("lib"), Some(_), Some(name), None) if name.ends_with(".so")
    )
}

fn payload_file_digests(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(path, digest)| (path.clone(), digest.to_ascii_lowercase()))
        .collect()
}

fn sha256_json(value: &impl serde::Serialize) -> RaspResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to serialize policy for digest calculation: {error}"),
        )
    })?;
    Ok(sha256_bytes(&bytes))
}

fn artifact_descriptor(path: &Path) -> RaspResult<ArtifactDescriptor> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to inspect artifact {}: {error}", path.display()),
        )
    })?;
    let sha256 = sha256_file(path)?;

    Ok(ArtifactDescriptor {
        path: path.display().to_string(),
        sha256,
        size_bytes: metadata.len(),
    })
}

fn sha256_file(path: &Path) -> RaspResult<String> {
    let mut file = File::open(path).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|error| {
            RaspError::new(
                ExitCode::GeneralProcessingFailure,
                format!("failed to read {}: {error}", path.display()),
            )
        })?;
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

fn sibling_json_path(apk_path: &Path, kind: &str) -> PathBuf {
    let stem = apk_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    apk_path.with_file_name(format!("{stem}.{kind}.json"))
}

fn default_signed_apk_path(unsigned_apk_path: &Path) -> String {
    let stem = unsigned_apk_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    unsigned_apk_path
        .with_file_name(format!("{stem}.signed.apk"))
        .display()
        .to_string()
}

fn write_json_file(path: &Path, value: &impl serde::Serialize) -> RaspResult<()> {
    let body = serde_json::to_string_pretty(value).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to serialize {}: {error}", path.display()),
        )
    })?;
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|error| {
            RaspError::new(
                ExitCode::GeneralProcessingFailure,
                format!("failed to create {}: {error}", parent.display()),
            )
        })?;
    }
    std::fs::write(path, format!("{body}\n")).map_err(|error| {
        RaspError::new(
            ExitCode::GeneralProcessingFailure,
            format!("failed to write {}: {error}", path.display()),
        )
    })
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn validate_optional_env_name(name: &str, value: Option<&str>) -> RaspResult<()> {
    let Some(value) = value else {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            format!("{name} is required for local signing"),
        ));
    };

    if !is_valid_env_var_name(value) {
        return Err(RaspError::new(
            ExitCode::InvalidCliArguments,
            format!("{name} must be an environment-variable name, not a value"),
        ));
    }

    Ok(())
}

fn write_or_print(path: Option<&PathBuf>, body: &str) -> RaspResult<()> {
    if let Some(path) = path {
        std::fs::write(path, body).map_err(|error| {
            RaspError::new(
                ExitCode::GeneralProcessingFailure,
                format!("failed to write {}: {error}", path.display()),
            )
        })?;
    } else {
        println!("{body}");
    }

    Ok(())
}

fn print_inspection_text(result: &InspectionResult) {
    println!("Artifact type: {:?}", result.artifact_type);
    println!("Path: {}", result.path.display());
    println!("Size: {} bytes", result.size_bytes);
    println!("SHA-256: {}", result.sha256);
    println!(
        "Package: {}",
        result.package_name.as_deref().unwrap_or("unknown")
    );
    println!(
        "Version: {} ({})",
        result.version_name.as_deref().unwrap_or("unknown"),
        result
            .version_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "SDK: min {}, target {}",
        result
            .min_sdk
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        result
            .target_sdk
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "React Native engine: {}",
        result
            .react_native_engine
            .map(|engine| format!("{engine:?}"))
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "JavaScript bundle: {}",
        result
            .javascript_bundle_path
            .as_deref()
            .unwrap_or("unknown")
    );
    if let Some(flutter) = result.flutter.as_ref() {
        println!("Flutter: detected");
        println!("Flutter app libraries: {}", flutter.app_libraries.len());
        println!(
            "Flutter engine libraries: {}",
            flutter.engine_libraries.len()
        );
        println!("Flutter asset entries: {}", flutter.asset_entries.len());
    } else {
        println!("Flutter: not detected");
    }
    println!(
        "Application class: {}",
        result.application_class.as_deref().unwrap_or("unknown")
    );
    println!(
        "Main activity: {}",
        result.main_activity.as_deref().unwrap_or("unknown")
    );
    println!(
        "extractNativeLibs: {}",
        result
            .extract_native_libs
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("DEX files: {}", result.dex_files.len());
    println!("Native libraries: {}", result.native_libraries.len());
    println!(
        "Supported ABIs: {}",
        if result.supported_abis.is_empty() {
            "none".to_string()
        } else {
            result.supported_abis.join(", ")
        }
    );
    println!("Content providers: {}", result.content_providers.len());
    println!(
        "Detected signing schemes: {}",
        if result.detected_signature_schemes.is_empty() {
            "none".to_string()
        } else {
            result
                .detected_signature_schemes
                .iter()
                .map(|scheme| format!("{scheme:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "Signing certificates: {}",
        result.signature_certificates.len()
    );
    for certificate in &result.signature_certificates {
        println!("Signing certificate SHA-256: {}", certificate.sha256);
    }
    println!("Signature entries: {}", result.signature_entries.len());
    println!("ZIP entries: {}", result.apk_compression.total_entries);

    if !result.existing_security_products.is_empty() {
        println!(
            "Existing security products: {}",
            result.existing_security_products.join(", ")
        );
    }

    for warning in &result.compatibility_warnings {
        println!("Compatibility warning: {warning}");
    }
    for warning in &result.warnings {
        println!("Warning: {warning}");
    }
}

#[derive(Debug)]
struct DoctorCheck {
    name: &'static str,
    required: bool,
    passed: bool,
    detail: Option<String>,
}

fn doctor_command(
    name: &'static str,
    executable: &str,
    args: &[&str],
    required: bool,
) -> DoctorCheck {
    doctor_command_path(name, Path::new(executable), args, required)
}

fn doctor_command_path(
    name: &'static str,
    executable: &Path,
    args: &[&str],
    required: bool,
) -> DoctorCheck {
    match Command::new(executable).args(args).output() {
        Ok(output) => {
            let combined_output = if output.stdout.is_empty() {
                String::from_utf8_lossy(&output.stderr).to_string()
            } else {
                String::from_utf8_lossy(&output.stdout).to_string()
            };
            DoctorCheck {
                name,
                required,
                passed: output.status.success(),
                detail: first_non_empty_line(&combined_output),
            }
        }
        Err(error) => DoctorCheck {
            name,
            required,
            passed: false,
            detail: Some(error.to_string()),
        },
    }
}

fn doctor_zipalign(executable: &Path) -> DoctorCheck {
    match Command::new(executable).output() {
        Ok(output) => {
            let combined_output = if output.stdout.is_empty() {
                String::from_utf8_lossy(&output.stderr).to_string()
            } else {
                String::from_utf8_lossy(&output.stdout).to_string()
            };
            let looks_like_zipalign = combined_output.contains("Zip alignment utility")
                || combined_output.contains("Usage: zipalign");
            DoctorCheck {
                name: "zipalign",
                required: true,
                passed: output.status.success() || looks_like_zipalign,
                detail: first_non_empty_line(&combined_output),
            }
        }
        Err(error) => DoctorCheck {
            name: "zipalign",
            required: true,
            passed: false,
            detail: Some(error.to_string()),
        },
    }
}

fn doctor_temp_dir() -> DoctorCheck {
    let temp_dir = std::env::temp_dir();
    let test_path = temp_dir.join(format!("rasp-cli-doctor-{}", std::process::id()));
    let result = std::fs::write(&test_path, b"test").and_then(|_| std::fs::remove_file(&test_path));

    DoctorCheck {
        name: "Temporary directory permissions",
        required: true,
        passed: result.is_ok(),
        detail: Some(format_path_with_result(&temp_dir, result.as_ref().err())),
    }
}

fn doctor_host_arch() -> DoctorCheck {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let supported =
        os == "linux" && arch == "x86_64" || os == "macos" && matches!(arch, "aarch64" | "x86_64");

    DoctorCheck {
        name: "Supported host architecture",
        required: true,
        passed: supported,
        detail: Some(format!("{arch}-{os}")),
    }
}

fn first_non_empty_line(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string)
}

fn format_path_with_result(path: &Path, error: Option<&std::io::Error>) -> String {
    match error {
        Some(error) => format!("{} ({error})", path.display()),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_payload_maximum_cli_version, default_signed_apk_path, is_hex_sha256,
        parse_native_library_args, protected_asset_paths, sibling_json_path,
    };
    use android_apk::IntegrityProtectedAssetKind;
    use artifact_inspector::{FlutterInfo, InspectionResult};
    use rasp_config::parse_config;
    use std::path::{Path, PathBuf};

    #[test]
    fn derives_default_external_artifact_paths() {
        let output = Path::new("build/app.unsigned.apk");

        assert_eq!(
            sibling_json_path(output, "signing-request"),
            Path::new("build/app.unsigned.signing-request.json")
        );
        assert_eq!(
            default_signed_apk_path(output),
            "build/app.unsigned.signed.apk"
        );
    }

    #[test]
    fn validates_sha256_hex_arguments() {
        assert!(is_hex_sha256(&"a".repeat(64)));
        assert!(is_hex_sha256(&"A".repeat(64)));
        assert!(!is_hex_sha256(&"a".repeat(63)));
        assert!(!is_hex_sha256(&"g".repeat(64)));
    }

    #[test]
    fn parses_native_library_arguments() {
        let parsed = parse_native_library_args(&[
            "arm64-v8a=/tmp/arm64/libsecurity.so".to_string(),
            "x86_64=/tmp/x86_64/libsecurity.so".to_string(),
        ])
        .expect("valid native library args");

        assert_eq!(
            parsed.get("arm64-v8a").map(PathBuf::as_path),
            Some(Path::new("/tmp/arm64/libsecurity.so"))
        );
        assert_eq!(
            parsed.get("x86_64").map(PathBuf::as_path),
            Some(Path::new("/tmp/x86_64/libsecurity.so"))
        );
    }

    #[test]
    fn rejects_invalid_native_library_arguments() {
        assert!(parse_native_library_args(&["arm64-v8a".to_string()]).is_err());
        assert!(parse_native_library_args(&["mips=/tmp/libsecurity.so".to_string()]).is_err());
        assert!(parse_native_library_args(&["arm64-v8a=".to_string()]).is_err());
        assert!(parse_native_library_args(&[
            "arm64-v8a=/tmp/one.so".to_string(),
            "arm64-v8a=/tmp/two.so".to_string()
        ])
        .is_err());
    }

    #[test]
    fn derives_default_payload_cli_major_range() {
        assert_eq!(default_payload_maximum_cli_version(), "0.x");
    }

    #[test]
    fn auto_selects_flutter_protected_assets_from_inspection() {
        let config = parse_config(
            r#"{
              "schema_version": 1,
              "application": {
                "profile": "flutter",
                "expected_package_name": "com.example.flutter",
                "build_environment": "release"
              },
              "protections": {
                "application_signature": { "enabled": true, "weight": 100 },
                "payload_integrity": { "enabled": true, "weight": 100 },
                "flutter_integrity": { "enabled": true, "weight": 80, "paths": [] }
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
                "supported_abis": ["arm64-v8a"],
                "initialize_processes": ["main"],
                "minimum_sdk": 23,
                "certificate_sha256": ["CURRENT_SIGNING_CERTIFICATE_SHA256"]
              }
            }"#,
        )
        .expect("valid config");
        let mut inspection = InspectionResult::unsupported(PathBuf::from("app.apk"));
        inspection.flutter = Some(FlutterInfo {
            detected: true,
            app_libraries: vec!["lib/arm64-v8a/libapp.so".to_string()],
            engine_libraries: vec!["lib/arm64-v8a/libflutter.so".to_string()],
            asset_entries: vec!["assets/flutter_assets/AssetManifest.json".to_string()],
        });

        let paths = protected_asset_paths(&config, &inspection);

        assert_eq!(
            paths.get("lib/arm64-v8a/libapp.so"),
            Some(&IntegrityProtectedAssetKind::FlutterNativeLibrary)
        );
        assert_eq!(
            paths.get("lib/arm64-v8a/libflutter.so"),
            Some(&IntegrityProtectedAssetKind::FlutterNativeLibrary)
        );
        assert_eq!(
            paths.get("assets/flutter_assets/AssetManifest.json"),
            Some(&IntegrityProtectedAssetKind::FlutterAsset)
        );
    }
}
