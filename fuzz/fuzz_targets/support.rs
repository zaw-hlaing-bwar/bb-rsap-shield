#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use android_apk::{
    default_runtime_policy, ApkRewriteOptions, IntegrityManifestInput, IntegrityProtectedAssetKind,
    IntegrityTool, PayloadFiles,
};
use android_axml::ManifestProvider;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MAX_FUZZ_INPUT_BYTES: usize = 512 * 1024;
const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = 0xffff_ffff;
const TYPE_STRING: u8 = 0x03;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn run_fuzzer(data: *const u8, size: usize, target: impl FnOnce(&[u8])) -> i32 {
    if data.is_null() {
        return 0;
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, size) };
    target(bytes);
    0
}

pub fn skip_large_input(data: &[u8]) -> bool {
    data.len() > MAX_FUZZ_INPUT_BYTES
}

pub fn with_temp_dir(prefix: &str, data: &[u8], run: impl FnOnce(&Path)) {
    if skip_large_input(data) {
        return;
    }

    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "bb-rsap-shield-fuzz-{prefix}-{}-{nonce}",
        std::process::id()
    ));
    if fs::create_dir_all(&root).is_err() {
        return;
    }

    run(&root);
    let _ = fs::remove_dir_all(&root);
}

pub fn package_name(data: &[u8]) -> String {
    format!("com.fuzz.{}", identifier_fragment(data, "app"))
}

pub fn provider_from_data(data: &[u8], package_name: &str) -> ManifestProvider {
    let exported = data.first().is_some_and(|byte| byte & 0x01 != 0);
    let init_order = if data.get(1).is_some_and(|byte| byte & 0x01 != 0) {
        Some(i32::from_le_bytes([
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
            data.get(4).copied().unwrap_or(0),
            data.get(5).copied().unwrap_or(0),
        ]))
    } else {
        None
    };

    let class_name = if data.get(6).is_some_and(|byte| byte % 8 == 0) {
        format!(
            "{}.{}.Provider",
            package_name,
            identifier_fragment(data, "runtime")
        )
    } else {
        "com.rasp.runtime.bootstrap.RaspInitProvider".to_string()
    };

    ManifestProvider {
        name: class_name,
        authorities: format!(
            "{package_name}.rasp.{}",
            identifier_fragment(data, "authority")
        ),
        exported,
        init_order,
    }
}

pub fn manifest_from_data(data: &[u8], package_name: &str) -> Vec<u8> {
    match data.first().copied().unwrap_or(0) % 5 {
        0 => data.to_vec(),
        1 => minimal_manifest(package_name),
        2 => mutated_manifest(data, package_name),
        3 => {
            let mut manifest = minimal_manifest(package_name);
            manifest.extend_from_slice(data.get(1..65).unwrap_or_default());
            manifest
        }
        _ => data.get(1..).unwrap_or_default().to_vec(),
    }
}

pub fn write_raw_or_structured_apk(path: &Path, data: &[u8], package_name: &str) -> io::Result<()> {
    if data.first().is_some_and(|byte| byte & 0x01 == 0) {
        fs::write(path, data)
    } else {
        write_structured_apk(path, data, package_name)
    }
}

pub fn write_structured_apk(path: &Path, data: &[u8], package_name: &str) -> io::Result<()> {
    let file = File::create(path)?;
    let mut writer = ZipWriter::new(file);
    let mut cursor = ByteCursor::new(data);

    match cursor.byte() % 5 {
        0 => {}
        1 => write_entry(
            &mut writer,
            "AndroidManifest.xml",
            &minimal_manifest(package_name),
            CompressionMethod::Deflated,
            false,
        )?,
        2 => write_entry(
            &mut writer,
            "AndroidManifest.xml",
            &mutated_manifest(data, package_name),
            CompressionMethod::Deflated,
            false,
        )?,
        3 => write_entry(
            &mut writer,
            "AndroidManifest.xml",
            data.get(1..).unwrap_or_default(),
            CompressionMethod::Stored,
            false,
        )?,
        _ => write_entry(
            &mut writer,
            "AndroidManifest.xml",
            &[],
            CompressionMethod::Deflated,
            false,
        )?,
    }

    let entry_count = 1 + usize::from(cursor.byte() % 24);
    for index in 0..entry_count {
        let name = entry_name(&mut cursor, index);
        let compression = if cursor.byte() & 0x01 == 0 {
            CompressionMethod::Deflated
        } else {
            CompressionMethod::Stored
        };
        let symlink = cursor.byte() % 31 == 0;
        let payload = cursor.take(512);
        let fallback_payload = fallback_entry_payload(&name);
        let bytes = if payload.is_empty() {
            fallback_payload.as_slice()
        } else {
            payload
        };
        write_entry(&mut writer, &name, bytes, compression, symlink)?;
    }

    writer.finish()?;
    Ok(())
}

pub fn write_payload_files(root: &Path) -> io::Result<PayloadFiles> {
    let bootstrap_dex_path = root.join("bootstrap.dex");
    let native_library_path = root.join("libsecurity.so");

    fs::write(&bootstrap_dex_path, b"dex\n035\0fuzz bootstrap")?;
    fs::write(&native_library_path, b"\x7fELFfuzz native library")?;

    Ok(PayloadFiles {
        bootstrap_dex_path,
        abi_libraries: BTreeMap::from([("arm64-v8a".to_string(), native_library_path)]),
    })
}

pub fn rewrite_options(expected_package_name: &str) -> ApkRewriteOptions {
    ApkRewriteOptions {
        build_id: "f001d00df001d00df001d00df001d00df001d00df001d00df001d00df001d00d".to_string(),
        provider_init_order: 1000,
        integrity_manifest: IntegrityManifestInput {
            application_profile: "fuzz".to_string(),
            build_environment: "test".to_string(),
            expected_package_name: expected_package_name.to_string(),
            policy_digest_sha256: "0".repeat(64),
            runtime_policy: default_runtime_policy(),
            expected_certificate_sha256: vec!["a".repeat(64)],
            payload_version: "fuzz-payload".to_string(),
            payload_file_sha256: BTreeMap::from([
                ("bootstrap.dex".to_string(), "1".repeat(64)),
                ("arm64-v8a/libsecurity.so".to_string(), "2".repeat(64)),
            ]),
            protected_asset_paths: BTreeMap::<String, IntegrityProtectedAssetKind>::new(),
            generated_by: IntegrityTool {
                name: "bb-rsap-shield-fuzz".to_string(),
                version: "0.0.0".to_string(),
            },
        },
    }
}

fn mutated_manifest(data: &[u8], package_name: &str) -> Vec<u8> {
    let mut manifest = minimal_manifest(package_name);
    if manifest.is_empty() {
        return manifest;
    }

    for (index, byte) in data.iter().take(96).enumerate() {
        let position = (usize::from(*byte) + index * 31) % manifest.len();
        manifest[position] ^= byte.rotate_left((index % 8) as u32);
    }

    manifest
}

fn write_entry(
    writer: &mut ZipWriter<File>,
    name: &str,
    bytes: &[u8],
    compression: CompressionMethod,
    symlink: bool,
) -> io::Result<()> {
    let mut options = SimpleFileOptions::default().compression_method(compression);
    options = if symlink {
        options.unix_permissions(0o120777)
    } else {
        options.unix_permissions(0o644)
    };

    writer.start_file(name, options)?;
    writer.write_all(bytes)
}

fn entry_name(cursor: &mut ByteCursor<'_>, index: usize) -> String {
    const INTERESTING_NAMES: &[&str] = &[
        "classes.dex",
        "classes2.dex",
        "classes10.dex",
        "assets/index.android.bundle",
        "assets/flutter_assets/AssetManifest.json",
        "assets/flutter_assets/kernel_blob.bin",
        "lib/arm64-v8a/libapp.so",
        "lib/arm64-v8a/libflutter.so",
        "lib/arm64-v8a/libhermes.so",
        "lib/arm64-v8a/libsecurity.so",
        "lib/armeabi-v7a/libapp.so",
        "lib/x86_64/libjsc.so",
        "META-INF/MANIFEST.MF",
        "META-INF/CERT.SF",
        "META-INF/CERT.RSA",
        "META-INF/CERT.EC",
        "assets/rasp-shield/integrity-manifest.json",
        "../classes.dex",
        "assets/../../secret",
        "..\\classes.dex",
        "/absolute.dex",
    ];

    if cursor.byte() % 5 == 0 {
        return format!(
            "assets/fuzz/{index}-{}.bin",
            identifier_fragment(cursor.take(24), "entry")
        );
    }

    INTERESTING_NAMES[usize::from(cursor.byte()) % INTERESTING_NAMES.len()].to_string()
}

fn fallback_entry_payload(name: &str) -> Vec<u8> {
    if name.ends_with(".dex") {
        b"dex\n035\0fuzz dex".to_vec()
    } else if name.ends_with(".so") {
        b"\x7fELFfuzz elf".to_vec()
    } else {
        name.as_bytes().to_vec()
    }
}

fn identifier_fragment(data: &[u8], fallback: &str) -> String {
    let mut output = String::new();
    for byte in data.iter().take(24) {
        let value = byte % 36;
        let character = if value < 26 {
            char::from(b'a' + value)
        } else {
            char::from(b'0' + (value - 26))
        };
        output.push(character);
    }

    if output.is_empty() {
        fallback.to_string()
    } else if output.as_bytes()[0].is_ascii_digit() {
        format!("p{output}")
    } else {
        output
    }
}

fn minimal_manifest(package_name: &str) -> Vec<u8> {
    let strings = vec!["manifest", "application", "package", package_name];
    let string_pool = build_string_pool(&strings);
    let manifest_index = string_index(&strings, "manifest");
    let application_index = string_index(&strings, "application");
    let package_index = string_index(&strings, "package");
    let package_value_index = string_index(&strings, package_name);

    let mut body = Vec::new();
    body.extend_from_slice(&string_pool);
    body.extend_from_slice(&start_element(
        manifest_index,
        &[(
            NO_INDEX,
            package_index,
            package_value_index,
            TYPE_STRING,
            package_value_index,
        )],
    ));
    body.extend_from_slice(&start_element(application_index, &[]));
    body.extend_from_slice(&end_element(application_index));
    body.extend_from_slice(&end_element(manifest_index));

    let mut output = Vec::new();
    write_u16(&mut output, RES_XML_TYPE);
    write_u16(&mut output, 8);
    write_u32(&mut output, (8 + body.len()) as u32);
    output.extend_from_slice(&body);
    output
}

fn build_string_pool(strings: &[&str]) -> Vec<u8> {
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
    write_u16(&mut output, RES_STRING_POOL_TYPE);
    write_u16(&mut output, 28);
    write_u32(&mut output, size as u32);
    write_u32(&mut output, strings.len() as u32);
    write_u32(&mut output, 0);
    write_u32(&mut output, UTF8_FLAG);
    write_u32(&mut output, strings_start as u32);
    write_u32(&mut output, 0);
    for offset in offsets {
        write_u32(&mut output, offset);
    }
    output.extend_from_slice(&data);
    output
}

fn start_element(name_index: u32, attributes: &[(u32, u32, u32, u8, u32)]) -> Vec<u8> {
    let size = 36 + attributes.len() * 20;
    let mut output = Vec::new();
    write_u16(&mut output, RES_XML_START_ELEMENT_TYPE);
    write_u16(&mut output, 16);
    write_u32(&mut output, size as u32);
    write_u32(&mut output, 0);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, NO_INDEX);
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

fn end_element(name_index: u32) -> Vec<u8> {
    let mut output = Vec::new();
    write_u16(&mut output, RES_XML_END_ELEMENT_TYPE);
    write_u16(&mut output, 16);
    write_u32(&mut output, 24);
    write_u32(&mut output, 0);
    write_u32(&mut output, NO_INDEX);
    write_u32(&mut output, NO_INDEX);
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

struct ByteCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let value = self.data[self.offset % self.data.len()];
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn take(&mut self, max_len: usize) -> &'a [u8] {
        if max_len == 0 || self.offset >= self.data.len() {
            return &[];
        }

        let selector = self.data[self.offset];
        self.offset = self.offset.saturating_add(1);
        if self.offset >= self.data.len() {
            return &[];
        }

        let available = self.data.len() - self.offset;
        let len = usize::from(selector) % (max_len.min(available) + 1);
        let start = self.offset;
        let end = start + len;
        self.offset = end;
        &self.data[start..end]
    }
}
