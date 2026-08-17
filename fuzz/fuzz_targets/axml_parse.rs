#![no_main]

mod support;

use android_axml::parse_manifest;

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    support::run_fuzzer(data, size, fuzz)
}

fn fuzz(data: &[u8]) {
    if support::skip_large_input(data) {
        return;
    }

    let _ = parse_manifest(data);

    let package_name = support::package_name(data);
    let manifest = support::manifest_from_data(data, &package_name);
    let _ = parse_manifest(&manifest);
}
