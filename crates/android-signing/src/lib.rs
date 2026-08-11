use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    Local,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidSigningTools {
    pub zipalign: PathBuf,
    pub apksigner: PathBuf,
}

impl Default for AndroidSigningTools {
    fn default() -> Self {
        Self {
            zipalign: find_android_build_tool("zipalign")
                .unwrap_or_else(|| PathBuf::from("zipalign")),
            apksigner: find_android_build_tool("apksigner")
                .unwrap_or_else(|| PathBuf::from("apksigner")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkSignOptions {
    pub keystore_path: PathBuf,
    pub key_alias: String,
    pub keystore_password_env: Option<String>,
    pub key_password_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecution {
    pub tool: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningToolError {
    #[error("failed to execute {tool}: {source}")]
    Io {
        tool: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{tool} failed with status {status}: {stderr}")]
    Failed {
        tool: String,
        status: String,
        stdout: String,
        stderr: String,
    },
}

pub fn align_apk(
    tools: &AndroidSigningTools,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<ToolExecution, SigningToolError> {
    run_tool(
        &tools.zipalign,
        [
            OsString::from("-P"),
            OsString::from("16"),
            OsString::from("-f"),
            OsString::from("-v"),
            OsString::from("4"),
            input.as_ref().as_os_str().to_os_string(),
            output.as_ref().as_os_str().to_os_string(),
        ],
    )
}

pub fn verify_alignment(
    tools: &AndroidSigningTools,
    input: impl AsRef<Path>,
) -> Result<ToolExecution, SigningToolError> {
    run_tool(
        &tools.zipalign,
        [
            OsString::from("-c"),
            OsString::from("-P"),
            OsString::from("16"),
            OsString::from("-v"),
            OsString::from("4"),
            input.as_ref().as_os_str().to_os_string(),
        ],
    )
}

pub fn sign_apk(
    tools: &AndroidSigningTools,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    options: &ApkSignOptions,
) -> Result<ToolExecution, SigningToolError> {
    let mut args = vec![
        OsString::from("sign"),
        OsString::from("--ks"),
        options.keystore_path.as_os_str().to_os_string(),
        OsString::from("--ks-key-alias"),
        OsString::from(&options.key_alias),
    ];
    if let Some(env_name) = &options.keystore_password_env {
        args.push(OsString::from("--ks-pass"));
        args.push(OsString::from(format!("env:{env_name}")));
    }
    if let Some(env_name) = &options.key_password_env {
        args.push(OsString::from("--key-pass"));
        args.push(OsString::from(format!("env:{env_name}")));
    }
    args.extend([
        OsString::from("--out"),
        output.as_ref().as_os_str().to_os_string(),
        input.as_ref().as_os_str().to_os_string(),
    ]);

    run_tool(&tools.apksigner, args)
}

pub fn verify_apk_signature(
    tools: &AndroidSigningTools,
    input: impl AsRef<Path>,
) -> Result<ToolExecution, SigningToolError> {
    run_tool(
        &tools.apksigner,
        [
            OsString::from("verify"),
            OsString::from("--verbose"),
            OsString::from("--print-certs"),
            input.as_ref().as_os_str().to_os_string(),
        ],
    )
}

pub fn redact_secret_argument(argument_name: &str, value: &str) -> String {
    if argument_name.contains("password") || argument_name.contains("secret") {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

fn run_tool(
    tool: &Path,
    args: impl IntoIterator<Item = OsString>,
) -> Result<ToolExecution, SigningToolError> {
    let tool_name = tool.display().to_string();
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|source| SigningToolError::Io {
            tool: tool_name.clone(),
            source,
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if output.status.success() {
        Ok(ToolExecution {
            tool: tool_name,
            stdout,
            stderr,
        })
    } else {
        Err(SigningToolError::Failed {
            tool: tool_name,
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "terminated by signal".to_string()),
            stdout,
            stderr,
        })
    }
}

fn find_android_build_tool(tool_name: &str) -> Option<PathBuf> {
    android_sdk_roots()
        .into_iter()
        .filter_map(|root| latest_build_tool_path(&root, tool_name))
        .next()
}

fn android_sdk_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for env_name in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(path) = std::env::var_os(env_name).filter(|value| !value.is_empty()) {
            roots.push(PathBuf::from(path));
        }
    }
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        roots.push(PathBuf::from(home).join("Library/Android/sdk"));
    }
    roots.sort();
    roots.dedup();
    roots
}

fn latest_build_tool_path(root: &Path, tool_name: &str) -> Option<PathBuf> {
    let build_tools = root.join("build-tools");
    let mut versions = fs::read_dir(build_tools)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .ok()
                .is_some_and(|file_type| file_type.is_dir())
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    versions.sort();
    versions.reverse();
    versions
        .into_iter()
        .map(|version| version.join(tool_name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::{
        align_apk, redact_secret_argument, sign_apk, verify_alignment, verify_apk_signature,
        AndroidSigningTools, ApkSignOptions,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn redacts_password_arguments() {
        assert_eq!(
            redact_secret_argument("keystore-password", "secret"),
            "<redacted>"
        );
        assert_eq!(
            redact_secret_argument("keystore", "release.keystore"),
            "release.keystore"
        );
    }

    #[test]
    #[cfg(unix)]
    fn invokes_zipalign_with_16k_page_alignment() {
        let root = create_temp_dir("zipalign");
        let log = root.join("args.log");
        let tool = fake_tool(&root, "zipalign", &log, 0);
        let tools = AndroidSigningTools {
            zipalign: tool,
            apksigner: PathBuf::from("unused"),
        };

        align_apk(&tools, "unsigned.apk", "aligned.apk").expect("align");
        assert_eq!(
            fs::read_to_string(&log).expect("read args"),
            "-P\n16\n-f\n-v\n4\nunsigned.apk\naligned.apk\n"
        );

        verify_alignment(&tools, "aligned.apk").expect("verify alignment");
        assert_eq!(
            fs::read_to_string(&log).expect("read verify args"),
            "-c\n-P\n16\n-v\n4\naligned.apk\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn invokes_apksigner_without_secret_values() {
        let root = create_temp_dir("apksigner");
        let log = root.join("args.log");
        let tool = fake_tool(&root, "apksigner", &log, 0);
        let tools = AndroidSigningTools {
            zipalign: PathBuf::from("unused"),
            apksigner: tool,
        };
        let options = ApkSignOptions {
            keystore_path: PathBuf::from("release.keystore"),
            key_alias: "release".to_string(),
            keystore_password_env: Some("KEYSTORE_PASSWORD".to_string()),
            key_password_env: Some("KEY_PASSWORD".to_string()),
        };

        sign_apk(&tools, "aligned.apk", "signed.apk", &options).expect("sign");
        let args = fs::read_to_string(&log).expect("read sign args");
        assert!(args.contains("--ks\nrelease.keystore\n"));
        assert!(args.contains("--ks-key-alias\nrelease\n"));
        assert!(args.contains("--ks-pass\nenv:KEYSTORE_PASSWORD\n"));
        assert!(args.contains("--key-pass\nenv:KEY_PASSWORD\n"));
        assert!(!args.contains("secret"));

        verify_apk_signature(&tools, "signed.apk").expect("verify signature");
        assert_eq!(
            fs::read_to_string(&log).expect("read verify args"),
            "verify\n--verbose\n--print-certs\nsigned.apk\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn reports_tool_failure() {
        let root = create_temp_dir("failure");
        let log = root.join("args.log");
        let tool = fake_tool(&root, "zipalign", &log, 2);
        let tools = AndroidSigningTools {
            zipalign: tool,
            apksigner: PathBuf::from("unused"),
        };

        let error = align_apk(&tools, "unsigned.apk", "aligned.apk").expect_err("failure");

        assert!(error.to_string().contains("failed with status 2"));
    }

    #[cfg(unix)]
    fn fake_tool(root: &Path, name: &str, log: &Path, status: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = root.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\n: > '{}'\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\" >> '{}'; done\nexit {status}\n",
                log.display(),
                log.display()
            ),
        )
        .expect("write fake tool");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod fake tool");
        path
    }

    fn create_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rasp-android-signing-{name}-{nonce}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
