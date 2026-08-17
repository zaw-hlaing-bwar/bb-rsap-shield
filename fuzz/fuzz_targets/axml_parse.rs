#![no_main]

mod support;

use android_axml::parse_manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fuzz(data));

fn fuzz(data: &[u8]) {
    if support::skip_large_input(data) {
        return;
    }

    let _ = parse_manifest(data);

    let package_name = support::package_name(data);
    let manifest = support::manifest_from_data(data, &package_name);
    let _ = parse_manifest(&manifest);
}
