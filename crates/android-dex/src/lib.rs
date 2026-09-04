pub const BOOTSTRAP_PACKAGE: &str = "com.rasp.runtime.bootstrap";
pub const BOOTSTRAP_PROVIDER_CLASS: &str = "com.rasp.runtime.bootstrap.RaspInitProvider";
pub const BOOTSTRAP_RUNTIME_CLASS: &str = "com.rasp.runtime.bootstrap.RaspRuntimeEntry";

const DEX_MAGIC_PREFIX: &[u8] = b"dex\n";
const DEX_CHECKSUM_OFFSET: usize = 8;
const DEX_SIGNATURE_OFFSET: usize = 12;
const DEX_SIGNATURE_END: usize = 32;
const DEX_HEADER_HASH_MIN_SIZE: usize = DEX_SIGNATURE_END;
const ADLER_MODULUS: u32 = 65_521;

pub fn bootstrap_provider_class_for_build_id(build_id: &str) -> Result<String, String> {
    if !is_hex_sha256(build_id) {
        return Err("build ID must be a 64-character SHA-256 hex digest".to_string());
    }
    let lower = build_id.to_ascii_lowercase();
    Ok(format!(
        "x.r{}.s{}.Rs{}Pr",
        &lower[..12],
        &lower[12..21],
        &lower[..12]
    ))
}

pub fn bootstrap_runtime_class_for_build_id(build_id: &str) -> Result<String, String> {
    if !is_hex_sha256(build_id) {
        return Err("build ID must be a 64-character SHA-256 hex digest".to_string());
    }
    let lower = build_id.to_ascii_lowercase();
    Ok(format!(
        "x.r{}.s{}.Rs{}Rt",
        &lower[..12],
        &lower[12..21],
        &lower[..12]
    ))
}

pub fn patch_bootstrap_provider_class(
    bytes: &[u8],
    replacement_class: &str,
) -> Result<Vec<u8>, String> {
    patch_class_name(bytes, BOOTSTRAP_PROVIDER_CLASS, replacement_class)
}

pub fn patch_bootstrap_runtime_class(
    bytes: &[u8],
    replacement_class: &str,
) -> Result<Vec<u8>, String> {
    patch_class_name(bytes, BOOTSTRAP_RUNTIME_CLASS, replacement_class)
}

fn patch_class_name(
    bytes: &[u8],
    original_class: &str,
    replacement_class: &str,
) -> Result<Vec<u8>, String> {
    let original = original_class.replace('.', "/");
    let replacement = replacement_class.replace('.', "/");
    if original.len() != replacement.len() {
        return Err(format!(
            "replacement bootstrap class for {original_class} must be {} bytes after slash conversion",
            original.len()
        ));
    }
    if !is_valid_java_class_name(replacement_class) {
        return Err("replacement bootstrap class is not a valid Java class name".to_string());
    }

    let mut output = bytes.to_vec();
    let replacements = replace_all_bytes(&mut output, original.as_bytes(), replacement.as_bytes());
    if replacements == 0 {
        return Err(format!(
            "bootstrap DEX does not contain expected class {original_class}"
        ));
    }

    if output.starts_with(DEX_MAGIC_PREFIX) && output.len() >= DEX_HEADER_HASH_MIN_SIZE {
        refresh_dex_header_hashes(&mut output);
    }

    Ok(output)
}

pub fn refresh_dex_header_hashes(bytes: &mut [u8]) {
    if output_starts_with_dex(bytes) && bytes.len() >= DEX_HEADER_HASH_MIN_SIZE {
        rewrite_dex_header_hashes(bytes);
    }
}

pub fn next_dex_name(existing_dex_count: usize) -> String {
    match existing_dex_count {
        0 | 1 => "classes2.dex".to_string(),
        count => format!("classes{}.dex", count + 1),
    }
}

pub fn next_dex_name_for_paths<'a>(paths: impl IntoIterator<Item = &'a String>) -> String {
    let max_index = paths
        .into_iter()
        .filter_map(|path| dex_index(path))
        .max()
        .unwrap_or(1);
    format!("classes{}.dex", max_index + 1)
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

fn output_starts_with_dex(bytes: &[u8]) -> bool {
    bytes.starts_with(DEX_MAGIC_PREFIX)
}

fn rewrite_dex_header_hashes(bytes: &mut [u8]) {
    let signature = sha1_digest(&bytes[DEX_SIGNATURE_END..]);
    bytes[DEX_SIGNATURE_OFFSET..DEX_SIGNATURE_END].copy_from_slice(&signature);
    let checksum = adler32(&bytes[DEX_SIGNATURE_OFFSET..]);
    bytes[DEX_CHECKSUM_OFFSET..DEX_SIGNATURE_OFFSET].copy_from_slice(&checksum.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % ADLER_MODULUS;
        b = (b + a) % ADLER_MODULUS;
    }
    (b << 16) | a
}

fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(((bytes.len() + 9).div_ceil(64)) * 64);
    message.extend_from_slice(bytes);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut h0 = 0x6745_2301u32;
    let mut h1 = 0xefcd_ab89u32;
    let mut h2 = 0x98ba_dcfeu32;
    let mut h3 = 0x1032_5476u32;
    let mut h4 = 0xc3d2_e1f0u32;

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut output = [0u8; 20];
    output[..4].copy_from_slice(&h0.to_be_bytes());
    output[4..8].copy_from_slice(&h1.to_be_bytes());
    output[8..12].copy_from_slice(&h2.to_be_bytes());
    output[12..16].copy_from_slice(&h3.to_be_bytes());
    output[16..20].copy_from_slice(&h4.to_be_bytes());
    output
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn is_valid_java_class_name(value: &str) -> bool {
    let mut segments = value.split('.');
    let mut segment_count = 0usize;
    for segment in &mut segments {
        segment_count += 1;
        if !is_valid_java_identifier(segment) {
            return false;
        }
    }
    segment_count >= 2
}

fn is_valid_java_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn dex_index(path: &str) -> Option<usize> {
    if path == "classes.dex" {
        return Some(1);
    }

    path.strip_prefix("classes")
        .and_then(|value| value.strip_suffix(".dex"))
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_provider_class_for_build_id, bootstrap_runtime_class_for_build_id,
        patch_bootstrap_provider_class, patch_bootstrap_runtime_class, BOOTSTRAP_PROVIDER_CLASS,
        BOOTSTRAP_RUNTIME_CLASS,
    };
    use super::{next_dex_name, next_dex_name_for_paths};

    #[test]
    fn selects_next_multidex_name() {
        assert_eq!(next_dex_name(1), "classes2.dex");
        assert_eq!(next_dex_name(2), "classes3.dex");
    }

    #[test]
    fn selects_next_dex_name_from_existing_paths() {
        let paths = vec![
            "classes.dex".to_string(),
            "classes2.dex".to_string(),
            "classes10.dex".to_string(),
            "assets/classes999.dex".to_string(),
        ];

        assert_eq!(next_dex_name_for_paths(&paths), "classes11.dex");
    }

    #[test]
    fn derives_same_length_provider_class_from_build_id() {
        let replacement =
            bootstrap_provider_class_for_build_id(&"a".repeat(64)).expect("provider class");

        assert_eq!(replacement.len(), BOOTSTRAP_PROVIDER_CLASS.len());
        assert_eq!(replacement, "x.raaaaaaaaaaaa.saaaaaaaaa.RsaaaaaaaaaaaaPr");
    }

    #[test]
    fn derives_same_length_runtime_class_from_build_id() {
        let replacement =
            bootstrap_runtime_class_for_build_id(&"b".repeat(64)).expect("runtime class");

        assert_eq!(replacement.len(), BOOTSTRAP_RUNTIME_CLASS.len());
        assert_eq!(replacement, "x.rbbbbbbbbbbbb.sbbbbbbbbb.RsbbbbbbbbbbbbRt");
    }

    #[test]
    fn patches_provider_class_prefixes_in_bootstrap_dex() {
        let replacement =
            bootstrap_provider_class_for_build_id(&"a".repeat(64)).expect("provider class");
        let original_slash = BOOTSTRAP_PROVIDER_CLASS.replace('.', "/");
        let replacement_slash = replacement.replace('.', "/");
        let dex = format!(
            "prefix L{}; middle L{}$RuntimePolicy; suffix",
            original_slash, original_slash
        )
        .into_bytes();

        let patched =
            patch_bootstrap_provider_class(&dex, &replacement).expect("patch provider class");
        let patched_text = String::from_utf8(patched).expect("patched utf8");

        assert!(!patched_text.contains(&original_slash));
        assert!(patched_text.contains(&format!("L{};", replacement_slash)));
        assert!(patched_text.contains(&format!("L{}$RuntimePolicy;", replacement_slash)));
    }

    #[test]
    fn patches_runtime_class_prefixes_in_runtime_dex() {
        let replacement =
            bootstrap_runtime_class_for_build_id(&"c".repeat(64)).expect("runtime class");
        let original_slash = BOOTSTRAP_RUNTIME_CLASS.replace('.', "/");
        let replacement_slash = replacement.replace('.', "/");
        let dex = format!(
            "prefix L{}; middle L{}$RuntimePolicy; suffix",
            original_slash, original_slash
        )
        .into_bytes();

        let patched =
            patch_bootstrap_runtime_class(&dex, &replacement).expect("patch runtime class");
        let patched_text = String::from_utf8(patched).expect("patched utf8");

        assert!(!patched_text.contains(&original_slash));
        assert!(patched_text.contains(&format!("L{};", replacement_slash)));
        assert!(patched_text.contains(&format!("L{}$RuntimePolicy;", replacement_slash)));
    }
}
