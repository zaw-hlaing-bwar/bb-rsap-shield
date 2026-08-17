#![no_main]

mod support;

use artifact_inspector::inspect_apk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fuzz(data));

fn fuzz(data: &[u8]) {
    let package_name = support::package_name(data);

    support::with_temp_dir("apk-inspect", data, |root| {
        let input = root.join("input.apk");
        if support::write_raw_or_structured_apk(&input, data, &package_name).is_ok() {
            let _ = inspect_apk(&input);
        }
    });
}
