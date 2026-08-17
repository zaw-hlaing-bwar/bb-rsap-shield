#![no_main]

mod support;

use android_axml::{inject_manifest_provider, parse_manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fuzz(data));

fn fuzz(data: &[u8]) {
    if support::skip_large_input(data) {
        return;
    }

    let package_name = support::package_name(data);
    let provider = support::provider_from_data(data, &package_name);

    let _ = inject_manifest_provider(data, &provider);

    let manifest = support::manifest_from_data(data, &package_name);
    if let Ok(updated) = inject_manifest_provider(&manifest, &provider) {
        let _ = parse_manifest(&updated);
        let _ = inject_manifest_provider(&updated, &provider);
    }
}
