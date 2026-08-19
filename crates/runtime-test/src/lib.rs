use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbTool {
    pub adb: PathBuf,
}

impl Default for AdbTool {
    fn default() -> Self {
        Self {
            adb: PathBuf::from("adb"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSmokeTestPlan {
    pub apk_path: PathBuf,
    pub package_name: String,
    pub launch_activity: Option<String>,
    pub device_serial: Option<String>,
    pub uninstall_after_test: bool,
    pub wait_after_launch_ms: u64,
}

impl RuntimeSmokeTestPlan {
    pub fn new(apk_path: impl Into<PathBuf>, package_name: impl Into<String>) -> Self {
        Self {
            apk_path: apk_path.into(),
            package_name: package_name.into(),
            launch_activity: None,
            device_serial: None,
            uninstall_after_test: true,
            wait_after_launch_ms: 1_500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSmokeTestReport {
    pub schema_version: u32,
    pub result: RuntimeSmokeTestResult,
    pub apk_path: String,
    pub package_name: String,
    pub launch_activity: Option<String>,
    pub device_serial: Option<String>,
    pub steps: Vec<RuntimeSmokeStep>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeSmokeTestResult {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSmokeStep {
    pub name: String,
    pub result: RuntimeSmokeStepResult,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeSmokeStepResult {
    Pass,
    Fail,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeSmokeError {
    #[error("runtime smoke-test validation failed: {0}")]
    Validation(String),
    #[error("failed to execute adb: {0}")]
    Io(#[from] std::io::Error),
}

pub fn run_runtime_smoke_test(
    adb_tool: &AdbTool,
    plan: &RuntimeSmokeTestPlan,
) -> Result<RuntimeSmokeTestReport, RuntimeSmokeError> {
    validate_plan(plan)?;

    let mut report = RuntimeSmokeTestReport {
        schema_version: 1,
        result: RuntimeSmokeTestResult::Pass,
        apk_path: plan.apk_path.display().to_string(),
        package_name: plan.package_name.clone(),
        launch_activity: plan.launch_activity.clone(),
        device_serial: plan.device_serial.clone(),
        steps: Vec::new(),
        warnings: Vec::new(),
    };

    if !record_adb_step(
        adb_tool,
        plan,
        &mut report,
        "device_state",
        [OsString::from("get-state")],
        |output| output.status_success && output.stdout.trim() == "device",
    )? {
        return Ok(fail(report));
    }

    if !record_adb_step(
        adb_tool,
        plan,
        &mut report,
        "install",
        [
            OsString::from("install"),
            OsString::from("-r"),
            OsString::from("-t"),
            plan.apk_path.as_os_str().to_os_string(),
        ],
        |output| output.status_success && output.combined_output().contains("Success"),
    )? {
        return Ok(fail(report));
    }

    if !record_adb_step(
        adb_tool,
        plan,
        &mut report,
        "clear_logcat",
        [OsString::from("logcat"), OsString::from("-c")],
        |output| output.status_success,
    )? {
        maybe_uninstall(adb_tool, plan, &mut report)?;
        return Ok(fail(report));
    }

    let launch_args = launch_args(plan);
    if !record_adb_step(
        adb_tool,
        plan,
        &mut report,
        "launch",
        launch_args,
        |output| {
            output.status_success
                && !output.combined_output().contains("Error")
                && !output.combined_output().contains("Exception")
        },
    )? {
        maybe_uninstall(adb_tool, plan, &mut report)?;
        return Ok(fail(report));
    }

    if plan.wait_after_launch_ms > 0 {
        thread::sleep(Duration::from_millis(plan.wait_after_launch_ms));
    }

    if !record_adb_step(
        adb_tool,
        plan,
        &mut report,
        "process_running",
        [
            OsString::from("shell"),
            OsString::from("pidof"),
            OsString::from(&plan.package_name),
        ],
        |output| output.status_success && !output.stdout.trim().is_empty(),
    )? {
        maybe_uninstall(adb_tool, plan, &mut report)?;
        return Ok(fail(report));
    }

    if !record_startup_budget_step(adb_tool, plan, &mut report)? {
        maybe_uninstall(adb_tool, plan, &mut report)?;
        return Ok(fail(report));
    }

    maybe_uninstall(adb_tool, plan, &mut report)?;
    Ok(report)
}

fn validate_plan(plan: &RuntimeSmokeTestPlan) -> Result<(), RuntimeSmokeError> {
    if !plan.apk_path.is_file() {
        return Err(RuntimeSmokeError::Validation(format!(
            "APK path must be an existing file: {}",
            plan.apk_path.display()
        )));
    }
    if plan.package_name.trim().is_empty() {
        return Err(RuntimeSmokeError::Validation(
            "package name must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn launch_args(plan: &RuntimeSmokeTestPlan) -> Vec<OsString> {
    if let Some(activity) = plan.launch_activity.as_deref() {
        vec![
            OsString::from("shell"),
            OsString::from("am"),
            OsString::from("start"),
            OsString::from("-W"),
            OsString::from("-n"),
            OsString::from(activity_component(&plan.package_name, activity)),
        ]
    } else {
        vec![
            OsString::from("shell"),
            OsString::from("monkey"),
            OsString::from("-p"),
            OsString::from(&plan.package_name),
            OsString::from("-c"),
            OsString::from("android.intent.category.LAUNCHER"),
            OsString::from("1"),
        ]
    }
}

fn activity_component(package_name: &str, activity: &str) -> String {
    if activity.contains('/') {
        activity.to_string()
    } else {
        format!("{package_name}/{activity}")
    }
}

fn maybe_uninstall(
    adb_tool: &AdbTool,
    plan: &RuntimeSmokeTestPlan,
    report: &mut RuntimeSmokeTestReport,
) -> Result<(), RuntimeSmokeError> {
    if !plan.uninstall_after_test {
        report
            .warnings
            .push("uninstall skipped by request".to_string());
        return Ok(());
    }

    record_adb_step(
        adb_tool,
        plan,
        report,
        "uninstall",
        [
            OsString::from("uninstall"),
            OsString::from(&plan.package_name),
        ],
        |output| output.status_success,
    )?;
    Ok(())
}

fn record_startup_budget_step(
    adb_tool: &AdbTool,
    plan: &RuntimeSmokeTestPlan,
    report: &mut RuntimeSmokeTestReport,
) -> Result<bool, RuntimeSmokeError> {
    let output = run_adb(
        adb_tool,
        plan.device_serial.as_deref(),
        [
            OsString::from("logcat"),
            OsString::from("-d"),
            OsString::from("-t"),
            OsString::from("2000"),
            OsString::from("-s"),
            OsString::from("RaspShield"),
        ],
    )?;
    let combined_output = output.combined_output();
    let observation = if output.status_success {
        parse_startup_budget_observation(&combined_output)
    } else {
        None
    };
    let detail = if output.status_success {
        observation
            .as_ref()
            .map(|observation| observation.detail())
            .unwrap_or_else(|| "missing RaspShield startup timing log".to_string())
    } else {
        output.first_detail_line()
    };
    let step_passed =
        output.status_success && observation.is_some_and(|observation| !observation.exceeded);
    report.steps.push(RuntimeSmokeStep {
        name: "startup_budget".to_string(),
        result: if step_passed {
            RuntimeSmokeStepResult::Pass
        } else {
            RuntimeSmokeStepResult::Fail
        },
        detail,
    });
    Ok(step_passed)
}

fn record_adb_step(
    adb_tool: &AdbTool,
    plan: &RuntimeSmokeTestPlan,
    report: &mut RuntimeSmokeTestReport,
    name: &str,
    args: impl IntoIterator<Item = OsString>,
    passed: impl FnOnce(&AdbOutput) -> bool,
) -> Result<bool, RuntimeSmokeError> {
    let output = run_adb(adb_tool, plan.device_serial.as_deref(), args)?;
    let step_passed = passed(&output);
    report.steps.push(RuntimeSmokeStep {
        name: name.to_string(),
        result: if step_passed {
            RuntimeSmokeStepResult::Pass
        } else {
            RuntimeSmokeStepResult::Fail
        },
        detail: output.first_detail_line(),
    });
    Ok(step_passed)
}

fn run_adb(
    adb_tool: &AdbTool,
    device_serial: Option<&str>,
    args: impl IntoIterator<Item = OsString>,
) -> Result<AdbOutput, RuntimeSmokeError> {
    let mut command = Command::new(&adb_tool.adb);
    if let Some(serial) = device_serial {
        command.arg("-s").arg(serial);
    }
    let output = command.args(args).output()?;
    Ok(AdbOutput {
        status_success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[derive(Debug)]
struct AdbOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

impl AdbOutput {
    fn combined_output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    fn first_detail_line(&self) -> String {
        self.combined_output()
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or(if self.status_success {
                "ok"
            } else {
                "adb failed"
            })
            .to_string()
    }
}

fn fail(mut report: RuntimeSmokeTestReport) -> RuntimeSmokeTestReport {
    report.result = RuntimeSmokeTestResult::Fail;
    report
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupBudgetObservation {
    duration_ms: u64,
    budget_ms: u64,
    exceeded: bool,
}

impl StartupBudgetObservation {
    fn detail(&self) -> String {
        format!(
            "startup_duration_ms={} startup_budget_ms={} startup_budget_exceeded={}",
            self.duration_ms, self.budget_ms, self.exceeded
        )
    }
}

fn parse_startup_budget_observation(logcat: &str) -> Option<StartupBudgetObservation> {
    let mut latest = None;
    for line in logcat.lines() {
        if !(line.contains("startup_duration_ms=")
            && line.contains("startup_budget_ms=")
            && line.contains("startup_budget_exceeded="))
        {
            continue;
        }

        if let Some(observation) = parse_startup_budget_line(line) {
            latest = Some(observation);
        }
    }
    latest
}

fn parse_startup_budget_line(line: &str) -> Option<StartupBudgetObservation> {
    let duration_ms = log_value(line, "startup_duration_ms=")?.parse().ok()?;
    let budget_ms = log_value(line, "startup_budget_ms=")?.parse().ok()?;
    let exceeded = match log_value(line, "startup_budget_exceeded=")? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    Some(StartupBudgetObservation {
        duration_ms,
        budget_ms,
        exceeded,
    })
}

fn log_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key))
        .map(|value| value.trim_end_matches(|character: char| !character.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_startup_budget_observation, run_runtime_smoke_test, RuntimeSmokeTestPlan,
        RuntimeSmokeTestResult,
    };
    use crate::AdbTool;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    #[test]
    #[cfg(unix)]
    fn installs_launches_checks_process_and_uninstalls() {
        let root = create_temp_dir("pass");
        let apk = root.join("app.apk");
        fs::write(&apk, b"apk").expect("write apk");
        let log = root.join("adb.log");
        let adb = fake_adb(&root, &log, FakeAdbMode::Pass);
        let mut plan = RuntimeSmokeTestPlan::new(&apk, "com.example.mobile");
        plan.wait_after_launch_ms = 0;

        let report = run_runtime_smoke_test(&AdbTool { adb }, &plan).expect("smoke test");

        assert_eq!(report.result, RuntimeSmokeTestResult::Pass);
        let log = fs::read_to_string(log).expect("read log");
        assert!(log.contains("get-state\n"));
        assert!(log.contains("install -r -t"));
        assert!(log.contains("logcat -c"));
        assert!(log.contains("shell monkey -p com.example.mobile"));
        assert!(log.contains("shell pidof com.example.mobile"));
        assert!(log.contains("logcat -d -t 2000 -s RaspShield"));
        assert!(log.contains("uninstall com.example.mobile"));
    }

    #[test]
    #[cfg(unix)]
    fn launches_explicit_activity_component() {
        let root = create_temp_dir("activity");
        let apk = root.join("app.apk");
        fs::write(&apk, b"apk").expect("write apk");
        let log = root.join("adb.log");
        let adb = fake_adb(&root, &log, FakeAdbMode::Pass);
        let mut plan = RuntimeSmokeTestPlan::new(&apk, "com.example.mobile");
        plan.launch_activity = Some(".MainActivity".to_string());
        plan.wait_after_launch_ms = 0;

        let report = run_runtime_smoke_test(&AdbTool { adb }, &plan).expect("smoke test");

        assert_eq!(report.result, RuntimeSmokeTestResult::Pass);
        assert!(fs::read_to_string(log)
            .expect("read log")
            .contains("shell am start -W -n com.example.mobile/.MainActivity"));
    }

    #[test]
    #[cfg(unix)]
    fn reports_process_failure() {
        let root = create_temp_dir("process-failure");
        let apk = root.join("app.apk");
        fs::write(&apk, b"apk").expect("write apk");
        let log = root.join("adb.log");
        let adb = fake_adb(&root, &log, FakeAdbMode::PidofFail);
        let mut plan = RuntimeSmokeTestPlan::new(&apk, "com.example.mobile");
        plan.wait_after_launch_ms = 0;

        let report = run_runtime_smoke_test(&AdbTool { adb }, &plan).expect("smoke test");

        assert_eq!(report.result, RuntimeSmokeTestResult::Fail);
        assert!(report
            .steps
            .iter()
            .any(|step| step.name == "process_running" && format!("{:?}", step.result) == "Fail"));
        assert!(fs::read_to_string(log)
            .expect("read log")
            .contains("uninstall com.example.mobile"));
    }

    #[test]
    #[cfg(unix)]
    fn reports_startup_budget_failure() {
        let root = create_temp_dir("startup-budget-failure");
        let apk = root.join("app.apk");
        fs::write(&apk, b"apk").expect("write apk");
        let log = root.join("adb.log");
        let adb = fake_adb(&root, &log, FakeAdbMode::StartupBudgetExceeded);
        let mut plan = RuntimeSmokeTestPlan::new(&apk, "com.example.mobile");
        plan.wait_after_launch_ms = 0;

        let report = run_runtime_smoke_test(&AdbTool { adb }, &plan).expect("smoke test");

        assert_eq!(report.result, RuntimeSmokeTestResult::Fail);
        assert!(report.steps.iter().any(|step| {
            step.name == "startup_budget"
                && format!("{:?}", step.result) == "Fail"
                && step.detail.contains("startup_budget_exceeded=true")
        }));
        assert!(fs::read_to_string(log)
            .expect("read log")
            .contains("uninstall com.example.mobile"));
    }

    #[test]
    fn parses_latest_startup_budget_log() {
        let observation = parse_startup_budget_observation(
            "08-19 01:00:00.000 I/RaspShield(123): startup_duration_ms=7 startup_budget_ms=50 startup_budget_exceeded=false initialized=true action=ALLOW\n\
             08-19 01:00:01.000 W/RaspShield(123): startup_duration_ms=75 startup_budget_ms=50 startup_budget_exceeded=true initialized=true action=ALLOW",
        )
        .expect("startup observation");

        assert_eq!(observation.duration_ms, 75);
        assert_eq!(observation.budget_ms, 50);
        assert!(observation.exceeded);
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeAdbMode {
        Pass,
        PidofFail,
        StartupBudgetExceeded,
    }

    #[cfg(unix)]
    fn fake_adb(root: &Path, log: &Path, mode: FakeAdbMode) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let pidof_status = match mode {
            FakeAdbMode::Pass => 0,
            FakeAdbMode::PidofFail => 1,
            FakeAdbMode::StartupBudgetExceeded => 0,
        };
        let pidof_output = match mode {
            FakeAdbMode::Pass => "1234",
            FakeAdbMode::PidofFail => "",
            FakeAdbMode::StartupBudgetExceeded => "1234",
        };
        let startup_log = match mode {
            FakeAdbMode::StartupBudgetExceeded => {
                "I/RaspShield: startup_duration_ms=75 startup_budget_ms=50 startup_budget_exceeded=true initialized=true action=ALLOW"
            }
            FakeAdbMode::Pass | FakeAdbMode::PidofFail => {
                "I/RaspShield: startup_duration_ms=7 startup_budget_ms=50 startup_budget_exceeded=false initialized=true action=ALLOW"
            }
        };
        let path = root.join("adb");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{}'
case "$*" in
  "get-state") echo device; exit 0 ;;
  install*) echo Success; exit 0 ;;
  "logcat -c") exit 0 ;;
  "shell monkey"*) echo "Events injected: 1"; exit 0 ;;
  "shell am start"*) echo "Status: ok"; exit 0 ;;
  "shell pidof"*) echo "{}"; exit {} ;;
  "logcat -d -t 2000 -s RaspShield") echo "{}"; exit 0 ;;
  uninstall*) echo Success; exit 0 ;;
esac
exit 0
"#,
                log.display(),
                pidof_output,
                pidof_status,
                startup_log
            ),
        )
        .expect("write fake adb");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod fake adb");
        path
    }

    fn create_temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rasp-runtime-test-{name}-{nonce}"));
        fs::create_dir_all(&root).expect("create temp dir");
        root
    }
}
