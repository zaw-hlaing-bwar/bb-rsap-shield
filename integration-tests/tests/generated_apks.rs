use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use android_apk::{
    default_runtime_policy, rewrite_unsigned_apk_with_payload, ApkRewriteOptions,
    IntegrityManifest, IntegrityManifestInput, IntegrityProtectedAssetKind, IntegrityTool,
    PayloadFiles, INTEGRITY_MANIFEST_ENTRY,
};
use android_axml::parse_manifest;
use artifact_inspector::{inspect_apk, ReactNativeEngine};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[test]
fn generated_react_native_variants_are_inspected() {
    let root = create_temp_dir("react-native-inspect");
    let hermes = root.join("hermes.apk");
    let jsc = root.join("jsc.apk");

    create_apk_with_entries(
        &hermes,
        &[
            (
                "AndroidManifest.xml",
                minimal_manifest("com.example.hermes"),
            ),
            ("classes.dex", b"dex\n035\0base".to_vec()),
            ("classes2.dex", b"dex\n035\0secondary".to_vec()),
            ("assets/index.android.bundle", b"hermes bundle".to_vec()),
            ("lib/arm64-v8a/libhermes.so", elf_bytes("hermes")),
        ],
    );
    create_apk_with_entries(
        &jsc,
        &[
            ("AndroidManifest.xml", minimal_manifest("com.example.jsc")),
            ("classes.dex", b"dex\n035\0base".to_vec()),
            ("assets/index.android.bundle", b"jsc bundle".to_vec()),
            ("lib/arm64-v8a/libjsc.so", elf_bytes("jsc")),
        ],
    );

    let hermes_result = inspect_apk(&hermes).expect("inspect Hermes APK");
    assert_eq!(
        hermes_result.package_name.as_deref(),
        Some("com.example.hermes")
    );
    assert_eq!(
        hermes_result.react_native_engine,
        Some(ReactNativeEngine::Hermes)
    );
    assert_eq!(
        hermes_result.javascript_bundle_path.as_deref(),
        Some("assets/index.android.bundle")
    );
    assert_eq!(
        hermes_result
            .dex_files
            .iter()
            .map(|dex| dex.path.as_str())
            .collect::<Vec<_>>(),
        vec!["classes.dex", "classes2.dex"]
    );

    let jsc_result = inspect_apk(&jsc).expect("inspect JSC APK");
    assert_eq!(jsc_result.package_name.as_deref(), Some("com.example.jsc"));
    assert_eq!(
        jsc_result.react_native_engine,
        Some(ReactNativeEngine::JavaScriptCore)
    );
    assert_eq!(jsc_result.supported_abis, vec!["arm64-v8a"]);
}

#[test]
fn generated_flutter_apk_is_inspected() {
    let root = create_temp_dir("flutter-inspect");
    let apk = root.join("flutter.apk");
    create_apk_with_entries(
        &apk,
        &[
            (
                "AndroidManifest.xml",
                minimal_manifest("com.example.flutter"),
            ),
            ("classes.dex", b"dex\n035\0base".to_vec()),
            ("lib/arm64-v8a/libapp.so", elf_bytes("flutter app")),
            ("lib/arm64-v8a/libflutter.so", elf_bytes("flutter engine")),
            ("assets/flutter_assets/AssetManifest.json", b"{}".to_vec()),
            ("assets/flutter_assets/kernel_blob.bin", b"kernel".to_vec()),
        ],
    );

    let result = inspect_apk(&apk).expect("inspect Flutter APK");
    let flutter = result.flutter.expect("Flutter should be detected");

    assert_eq!(result.package_name.as_deref(), Some("com.example.flutter"));
    assert_eq!(flutter.app_libraries, vec!["lib/arm64-v8a/libapp.so"]);
    assert_eq!(
        flutter.engine_libraries,
        vec!["lib/arm64-v8a/libflutter.so"]
    );
    assert_eq!(
        flutter.asset_entries,
        vec![
            "assets/flutter_assets/AssetManifest.json",
            "assets/flutter_assets/kernel_blob.bin"
        ]
    );
}

#[test]
fn generated_apk_can_be_rewritten_with_payload() {
    let root = create_temp_dir("rewrite");
    let input = root.join("input.apk");
    let output = root.join("output.apk");
    create_apk_with_entries(
        &input,
        &[
            (
                "AndroidManifest.xml",
                minimal_manifest("com.example.mobile"),
            ),
            ("classes.dex", b"dex\n035\0base".to_vec()),
            ("classes2.dex", b"dex\n035\0secondary".to_vec()),
            ("assets/index.android.bundle", b"bundle".to_vec()),
            ("lib/arm64-v8a/libapp.so", elf_bytes("flutter app")),
            ("assets/flutter_assets/AssetManifest.json", b"{}".to_vec()),
            ("META-INF/MANIFEST.MF", b"manifest signature".to_vec()),
            ("META-INF/CERT.SF", b"sf signature".to_vec()),
            ("META-INF/CERT.RSA", b"rsa signature".to_vec()),
        ],
    );
    let bootstrap_dex = root.join("bootstrap.dex");
    let native_library = root.join("libsecurity.so");
    fs::write(&bootstrap_dex, b"dex\n035\0payload").expect("write bootstrap");
    fs::write(&native_library, elf_bytes("security")).expect("write native library");

    let payload = PayloadFiles {
        bootstrap_dex_path: bootstrap_dex,
        abi_libraries: BTreeMap::from([("arm64-v8a".to_string(), native_library)]),
    };
    let report = rewrite_unsigned_apk_with_payload(&input, &output, &payload, &rewrite_options())
        .expect("rewrite generated APK");

    assert_eq!(report.inserted_dex_entry, "classes3.dex");
    assert_eq!(
        report.inserted_native_library_entries,
        vec!["lib/arm64-v8a/libsecurity.so"]
    );

    let rewritten = inspect_apk(&output).expect("inspect rewritten APK");
    assert!(rewritten.detected_signature_schemes.is_empty());
    assert!(rewritten.signature_entries.is_empty());

    let mut archive =
        ZipArchive::new(File::open(&output).expect("open output APK")).expect("read output APK");
    assert!(archive.by_name("META-INF/CERT.RSA").is_err());
    assert_eq!(
        read_zip_entry(&mut archive, "classes3.dex"),
        b"dex\n035\0payload"
    );

    let manifest = parse_manifest(&read_zip_entry(&mut archive, "AndroidManifest.xml"))
        .expect("parse rewritten manifest");
    assert!(manifest.providers.iter().any(|provider| {
        provider.name.as_deref() == Some("com.rasp.runtime.bootstrap.RaspInitProvider")
            && provider.exported == Some(false)
    }));

    let integrity_manifest: IntegrityManifest =
        serde_json::from_slice(&read_zip_entry(&mut archive, INTEGRITY_MANIFEST_ENTRY))
            .expect("parse integrity manifest");
    assert!(integrity_manifest
        .protected_assets
        .iter()
        .any(|asset| asset.path == "assets/index.android.bundle"
            && asset.kind == IntegrityProtectedAssetKind::JavascriptBundle));
    assert!(
        integrity_manifest
            .policy
            .runtime
            .detections
            .instrumentation
            .enabled
    );
}

#[test]
fn generated_malformed_apks_fail_closed() {
    let root = create_temp_dir("malformed");
    let missing_manifest = root.join("missing-manifest.apk");
    let zip_slip = root.join("zip-slip.apk");

    create_apk_with_entries(
        &missing_manifest,
        &[("classes.dex", b"dex\n035\0base".to_vec())],
    );
    create_apk_with_entries(
        &zip_slip,
        &[
            (
                "AndroidManifest.xml",
                minimal_manifest("com.example.mobile"),
            ),
            ("../classes.dex", b"dex\n035\0evil".to_vec()),
        ],
    );

    let missing_manifest_error = inspect_apk(&missing_manifest)
        .expect_err("APK without manifest should fail inspection")
        .to_string();
    assert!(missing_manifest_error.contains("missing AndroidManifest.xml"));

    let zip_slip_error = inspect_apk(&zip_slip)
        .expect_err("ZIP-slip APK should fail inspection")
        .to_string();
    assert!(zip_slip_error.contains("ZIP-slip paths found"));
}

fn rewrite_options() -> ApkRewriteOptions {
    ApkRewriteOptions {
        build_id: "a91f30c2d41e8bf0d9d8f3e14a47d2e4a9c3617e57df9b36f9fcff1977b8b18a".to_string(),
        provider_init_order: 1000,
        integrity_manifest: IntegrityManifestInput {
            application_profile: "integration".to_string(),
            build_environment: "test".to_string(),
            expected_package_name: "com.example.mobile".to_string(),
            policy_digest_sha256: "0".repeat(64),
            runtime_policy: default_runtime_policy(),
            expected_certificate_sha256: vec!["a".repeat(64)],
            payload_version: "integration-payload".to_string(),
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
                name: "rasp-integration-tests".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        },
    }
}

fn create_temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("rasp-generated-apk-{name}-{nonce}"));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

fn create_apk_with_entries(path: &Path, entries: &[(&str, Vec<u8>)]) {
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

fn elf_bytes(label: &str) -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend_from_slice(label.as_bytes());
    bytes
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
    let string_pool = build_string_pool(&strings, RES_STRING_POOL_TYPE, UTF8_FLAG);
    let manifest_index = string_index(&strings, "manifest");
    let application_index = string_index(&strings, "application");
    let package_index = string_index(&strings, "package");
    let package_value_index = string_index(&strings, package_name);

    let mut body = Vec::new();
    body.extend_from_slice(&string_pool);
    body.extend_from_slice(&start_element(
        RES_XML_START_ELEMENT_TYPE,
        NO_INDEX,
        manifest_index,
        &[(
            NO_INDEX,
            package_index,
            package_value_index,
            TYPE_STRING,
            package_value_index,
        )],
    ));
    body.extend_from_slice(&start_element(
        RES_XML_START_ELEMENT_TYPE,
        NO_INDEX,
        application_index,
        &[],
    ));
    body.extend_from_slice(&end_element(
        RES_XML_END_ELEMENT_TYPE,
        NO_INDEX,
        application_index,
    ));
    body.extend_from_slice(&end_element(
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

fn build_string_pool(strings: &[&str], chunk_type: u16, flags: u32) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for value in strings {
        offsets.push(data.len() as u32);
        encode_length8(&mut data, value.encode_utf16().count());
        encode_length8(&mut data, value.len());
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

fn start_element(
    chunk_type: u16,
    no_index: u32,
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

fn end_element(chunk_type: u16, no_index: u32, name_index: u32) -> Vec<u8> {
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

fn encode_length8(output: &mut Vec<u8>, length: usize) {
    if length <= 0x7f {
        output.push(length as u8);
    } else {
        output.push(((length >> 8) as u8) | 0x80);
        output.push((length & 0xff) as u8);
    }
}

fn string_index(strings: &[&str], value: &str) -> u32 {
    strings
        .iter()
        .position(|existing| *existing == value)
        .expect("string exists") as u32
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}
