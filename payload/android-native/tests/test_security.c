#include "rasp_security.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int has_signal(const RaspSecurityReport *report, const char *id) {
  for (uint32_t index = 0U; index < report->signal_count; index++) {
    if (strcmp(report->signals[index].id, id) == 0) {
      return 1;
    }
  }
  return 0;
}

static uint8_t signal_weight(const RaspSecurityReport *report, const char *id) {
  for (uint32_t index = 0U; index < report->signal_count; index++) {
    if (strcmp(report->signals[index].id, id) == 0) {
      return report->signals[index].weight;
    }
  }
  return 0U;
}

static void detects_instrumentation_maps(void) {
  static const char maps[] =
      "70000000-70100000 r-xp 00000000 fd:00 1 /data/app/libFRIDA-gadget.so\n"
      "70100000-70200000 r-xp 00000000 fd:00 2 /data/adb/modules/zygisk/libhook.so\n"
      "70110000-70120000 r-xp 00000000 fd:00 3 /data/app/libdobby.so\n"
      "70200000-70300000 rwxp 00000000 00:00 0 [anon:jit-cache]\n";
  RaspSecurityReport report;

  assert(rasp_security_test_scan_maps_text(maps, &report) == 0);
  assert(has_signal(&report, "instrumentation.frida_library"));
  assert(has_signal(&report, "instrumentation.zygisk_module"));
  assert(has_signal(&report, "instrumentation.native_hook_framework"));
  assert(has_signal(&report, "memory.writable_executable_map"));
  assert(report.risk_score == 100U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void caps_risk_score(void) {
  static const char maps[] =
      "70000000-70100000 r-xp 00000000 fd:00 1 /data/app/libfrida-gadget.so\n"
      "70100000-70200000 r-xp 00000000 fd:00 2 /data/app/libxposed.so\n"
      "70200000-70300000 r-xp 00000000 fd:00 3 /data/app/libsubstrate.so\n"
      "70300000-70400000 r-xp 00000000 fd:00 4 /data/adb/modules/zygisk/libhook.so\n";
  RaspSecurityReport report;

  assert(rasp_security_test_scan_maps_text(maps, &report) == 0);
  assert(report.risk_score == 100U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_thread_names(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_thread_name("gum-js-loop", &report) == 0);
  assert(has_signal(&report, "instrumentation.frida_thread"));
  assert(report.risk_score == 35U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);

  assert(rasp_security_test_scan_thread_name("gmain", &report) == 0);
  assert(has_signal(&report, "instrumentation.glib_thread"));
  assert(report.risk_score == 20U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_tracer_pid(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_status_text("Name:\tapp\nTracerPid:\t42\n",
                                             &report) == 0);
  assert(has_signal(&report, "debugger.tracer_pid"));
  assert(report.risk_score == 30U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_frida_default_ports(void) {
  static const char tcp[] =
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
      "   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000\n";
  RaspSecurityReport report;

  assert(rasp_security_test_scan_tcp_text(tcp, &report) == 0);
  assert(has_signal(&report, "instrumentation.frida_default_port"));
  assert(report.risk_score == 10U);
  assert(report.action == RASP_SECURITY_ACTION_ALLOW);
}

static void detects_frida_unix_socket(void) {
  static const char unix_sockets[] =
      "Num RefCount Protocol Flags Type St Inode Path\n"
      "0000000000000000: 00000002 00000000 00010000 0001 01 1 @frida-helper\n";
  RaspSecurityReport report;

  assert(rasp_security_test_scan_unix_text(unix_sockets, &report) == 0);
  assert(has_signal(&report, "instrumentation.frida_unix_socket"));
  assert(report.risk_score == 25U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void disables_proc_net_scans_after_permission_denial(void) {
  assert(rasp_security_test_proc_net_scan_disabled_after_error(EACCES) == 1);
  assert(rasp_security_test_proc_net_scan_disabled_after_error(EPERM) == 1);
  assert(rasp_security_test_proc_net_scan_disabled_after_error(ENOENT) == 0);
}

static void detects_suspicious_environment(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_environment_text(
             "PATH=/system/bin\nLD_PRELOAD=/data/local/tmp/libhook.so\n",
             &report) == 0);
  assert(has_signal(&report, "instrumentation.suspicious_environment"));
  assert(report.risk_score == 25U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void runtime_policy_disables_instrumentation_signals(void) {
  static const char maps[] =
      "70000000-70100000 r-xp 00000000 fd:00 1 /data/app/libfrida-gadget.so\n"
      "70200000-70300000 rwxp 00000000 00:00 0 [anon:jit-cache]\n";
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  policy.instrumentation_detection_enabled = 0U;

  assert(rasp_security_test_scan_maps_text(maps, &report) == 0);
  assert(rasp_security_test_apply_runtime_detector_policy(&report, &policy) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(!has_signal(&report, "instrumentation.frida_library"));
  assert(has_signal(&report, "memory.writable_executable_map"));
  assert(report.risk_score == 15U);
  assert(report.action == RASP_SECURITY_ACTION_ALLOW);
}

static void runtime_policy_caps_debugger_signal_weight(void) {
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  policy.debugger_detection_weight = 10U;

  assert(rasp_security_test_scan_status_text("Name:\tapp\nTracerPid:\t42\n",
                                             &report) == 0);
  assert(rasp_security_test_apply_runtime_detector_policy(&report, &policy) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(has_signal(&report, "debugger.tracer_pid"));
  assert(signal_weight(&report, "debugger.tracer_pid") == 10U);
  assert(report.risk_score == 10U);
  assert(report.action == RASP_SECURITY_ACTION_ALLOW);
}

static void detects_root_paths(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_root_paths_text("/system/xbin/su", &report) == 0);
  assert(has_signal(&report, "root.su_binary"));
  assert(report.risk_score == 20U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_root_properties(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_root_properties_text(
             "ro.build.tags=release-keys,test-keys\n"
             "ro.secure=0\n"
             "ro.boot.vbmeta.device_state=unlocked\n",
             &report) == 0);
  assert(has_signal(&report, "root.test_keys"));
  assert(has_signal(&report, "root.insecure_system_property"));
  assert(has_signal(&report, "root.bootloader_unlocked"));
  assert(report.risk_score == 60U);
  assert(report.action == RASP_SECURITY_ACTION_WARN);
}

static void detects_root_mounts(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_root_mounts_text(
             "/dev/block/dm-0 /system ext4 rw,seclabel,relatime 0 0\n",
             &report) == 0);
  assert(has_signal(&report, "root.writable_system_partition"));
  assert(report.risk_score == 20U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_emulator_build_fields(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_emulator_build_text(
             "FINGERPRINT=google/sdk_gphone64_arm64/emulator:15\n",
             &report) == 0);
  assert(has_signal(&report, "emulator.build_profile"));
  assert(report.risk_score == 10U);
  assert(report.action == RASP_SECURITY_ACTION_ALLOW);
}

static void detects_emulator_properties(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_emulator_properties_text(
             "ro.kernel.qemu=1\nro.hardware=ranchu\n",
             &report) == 0);
  assert(has_signal(&report, "emulator.qemu_property"));
  assert(has_signal(&report, "emulator.build_profile"));
  assert(report.risk_score == 20U);
  assert(report.action == RASP_SECURITY_ACTION_REPORT);
}

static void detects_emulator_cpuinfo(void) {
  RaspSecurityReport report;

  assert(rasp_security_test_scan_emulator_cpuinfo_text(
             "Hardware\t: Goldfish\n",
             &report) == 0);
  assert(has_signal(&report, "emulator.cpuinfo"));
  assert(report.risk_score == 10U);
  assert(report.action == RASP_SECURITY_ACTION_ALLOW);
}

static void applies_configured_high_risk_action(void) {
  static const char maps[] =
      "70000000-70100000 r-xp 00000000 fd:00 1 /data/app/libfrida-gadget.so\n"
      "70100000-70200000 r-xp 00000000 fd:00 2 /data/adb/modules/zygisk/libhook.so\n";
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  policy.runtime_high_risk_action = RASP_SECURITY_ACTION_TERMINATE;

  assert(rasp_security_test_scan_maps_text(maps, &report) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(report.risk_score == 80U);
  assert(report.action == RASP_SECURITY_ACTION_TERMINATE);
}

static void startup_identity_mismatch_takes_precedence(void) {
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  assert(rasp_security_test_scan_tcp_text("", &report) == 0);
  assert(rasp_security_add_startup_identity_signals(&report, 0, 1) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(has_signal(&report, "startup.package_mismatch"));
  assert(report.risk_score == 100U);
  assert(report.action == RASP_SECURITY_ACTION_TERMINATE);
}

static void startup_payload_tampering_takes_precedence(void) {
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  policy.startup_payload_tampering_action = RASP_SECURITY_ACTION_LOCK_STARTUP;

  assert(rasp_security_test_scan_tcp_text("", &report) == 0);
  assert(rasp_security_add_startup_payload_signals(&report, 0, 1) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(has_signal(&report, "startup.payload_integrity_mismatch"));
  assert(report.risk_score == 100U);
  assert(report.action == RASP_SECURITY_ACTION_LOCK_STARTUP);
}

static void runtime_payload_tampering_takes_precedence(void) {
  RaspSecurityPolicy policy = rasp_security_default_policy();
  RaspSecurityReport report;

  policy.runtime_high_risk_action = RASP_SECURITY_ACTION_REPORT;
  policy.startup_payload_tampering_action = RASP_SECURITY_ACTION_TERMINATE;

  assert(rasp_security_test_scan_tcp_text("", &report) == 0);
  assert(rasp_security_add_runtime_payload_signals(&report, 0) == 0);
  assert(rasp_security_apply_policy(&report, &policy) == 0);
  assert(has_signal(&report, "runtime.protected_asset_mismatch"));
  assert(report.risk_score == 80U);
  assert(report.action == RASP_SECURITY_ACTION_TERMINATE);
}

static void emits_json_report(void) {
  RaspSecurityReport report;
  char json[RASP_SECURITY_REPORT_JSON_SIZE];

  assert(rasp_security_test_scan_thread_name("pool-frida", &report) == 0);
  assert(rasp_security_report_to_json(&report, json, sizeof(json)) > 0U);
  assert(strstr(json, "\"risk_score\":35") != NULL);
  assert(strstr(json, "\"action\":\"REPORT\"") != NULL);
  assert(strstr(json, "instrumentation.frida_thread") != NULL);
}

int main(void) {
  detects_instrumentation_maps();
  caps_risk_score();
  detects_thread_names();
  detects_tracer_pid();
  detects_frida_default_ports();
  detects_frida_unix_socket();
  disables_proc_net_scans_after_permission_denial();
  detects_suspicious_environment();
  runtime_policy_disables_instrumentation_signals();
  runtime_policy_caps_debugger_signal_weight();
  detects_root_paths();
  detects_root_properties();
  detects_root_mounts();
  detects_emulator_build_fields();
  detects_emulator_properties();
  detects_emulator_cpuinfo();
  applies_configured_high_risk_action();
  startup_identity_mismatch_takes_precedence();
  startup_payload_tampering_takes_precedence();
  runtime_payload_tampering_takes_precedence();
  emits_json_report();
  puts("rasp_security_tests: ok");
  return 0;
}
