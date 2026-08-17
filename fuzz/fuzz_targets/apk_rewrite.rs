#![no_main]

mod support;

use android_apk::rewrite_unsigned_apk_with_payload;
use artifact_inspector::inspect_apk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fuzz(data));

fn fuzz(data: &[u8]) {
    let expected_package_name = "com.example.mobile";

    support::with_temp_dir("apk-rewrite", data, |root| {
        let input = root.join("input.apk");
        let output = root.join("output.apk");
        if support::write_structured_apk(&input, data, expected_package_name).is_err() {
            return;
        }

        let Ok(payload_files) = support::write_payload_files(root) else {
            return;
        };
        let options = support::rewrite_options(expected_package_name);

        if rewrite_unsigned_apk_with_payload(&input, &output, &payload_files, &options).is_ok() {
            let _ = inspect_apk(&output);
        }
    });
}
