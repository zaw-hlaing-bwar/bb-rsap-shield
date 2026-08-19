#ifndef RASP_SECURITY_H
#define RASP_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RASP_SECURITY_DETECTOR_VERSION 2U
#define RASP_SECURITY_MAX_SIGNALS 32U
#define RASP_SECURITY_SIGNAL_ID_SIZE 64U
#define RASP_SECURITY_SIGNAL_CATEGORY_SIZE 32U
#define RASP_SECURITY_SIGNAL_EVIDENCE_SIZE 128U
#define RASP_SECURITY_ACTION_REASON_SIZE 96U
#define RASP_SECURITY_REPORT_JSON_SIZE 4096U

typedef enum RaspSecurityAction {
  RASP_SECURITY_ACTION_ALLOW = 0,
  RASP_SECURITY_ACTION_REPORT = 1,
  RASP_SECURITY_ACTION_WARN = 2,
  RASP_SECURITY_ACTION_LOCK_STARTUP = 3,
  RASP_SECURITY_ACTION_TERMINATE = 4
} RaspSecurityAction;

typedef struct RaspSecurityPolicy {
  uint8_t report_threshold;
  uint8_t warn_threshold;
  uint8_t restrict_threshold;
  uint8_t terminate_threshold;
  RaspSecurityAction runtime_high_risk_action;
  RaspSecurityAction startup_integrity_action;
  RaspSecurityAction startup_payload_tampering_action;
  uint8_t debugger_detection_enabled;
  uint8_t debugger_detection_weight;
  uint8_t instrumentation_detection_enabled;
  uint8_t instrumentation_detection_weight;
  uint8_t memory_integrity_enabled;
  uint8_t memory_integrity_weight;
  uint8_t root_detection_enabled;
  uint8_t root_detection_weight;
  uint8_t emulator_detection_enabled;
  uint8_t emulator_detection_weight;
} RaspSecurityPolicy;

typedef struct RaspSecuritySignal {
  char id[RASP_SECURITY_SIGNAL_ID_SIZE];
  char category[RASP_SECURITY_SIGNAL_CATEGORY_SIZE];
  uint8_t confidence;
  uint8_t severity;
  uint8_t weight;
  char evidence[RASP_SECURITY_SIGNAL_EVIDENCE_SIZE];
} RaspSecuritySignal;

typedef struct RaspSecurityReport {
  uint32_t detector_version;
  uint32_t signal_count;
  uint32_t risk_score;
  RaspSecurityAction action;
  char action_reason[RASP_SECURITY_ACTION_REASON_SIZE];
  RaspSecuritySignal signals[RASP_SECURITY_MAX_SIGNALS];
} RaspSecurityReport;

int rasp_security_initialize(void);
int rasp_security_collect(RaspSecurityReport *report);
RaspSecurityPolicy rasp_security_default_policy(void);
RaspSecurityAction rasp_security_action_from_name(const char *name);
const char *rasp_security_action_name(RaspSecurityAction action);
int rasp_security_add_startup_identity_signals(RaspSecurityReport *report,
                                               int package_matches,
                                               int certificate_matches);
int rasp_security_add_startup_payload_signals(RaspSecurityReport *report,
                                              int payload_matches,
                                              int protected_assets_match);
int rasp_security_add_runtime_payload_signals(RaspSecurityReport *report,
                                              int protected_assets_match);
int rasp_security_apply_policy(RaspSecurityReport *report,
                               const RaspSecurityPolicy *policy);
const RaspSecurityReport *rasp_security_last_report(void);
size_t rasp_security_report_to_json(const RaspSecurityReport *report, char *buffer,
                                    size_t buffer_size);
size_t rasp_security_last_report_json(char *buffer, size_t buffer_size);

#ifdef RASP_SECURITY_TEST
int rasp_security_test_scan_maps_text(const char *text, RaspSecurityReport *report);
int rasp_security_test_scan_status_text(const char *text, RaspSecurityReport *report);
int rasp_security_test_scan_thread_name(const char *name, RaspSecurityReport *report);
int rasp_security_test_scan_tcp_text(const char *text, RaspSecurityReport *report);
int rasp_security_test_scan_unix_text(const char *text, RaspSecurityReport *report);
int rasp_security_test_proc_net_scan_disabled_after_error(int error_code);
int rasp_security_test_scan_environment_text(const char *text,
                                             RaspSecurityReport *report);
int rasp_security_test_scan_root_paths_text(const char *text,
                                            RaspSecurityReport *report);
int rasp_security_test_scan_root_properties_text(const char *text,
                                                 RaspSecurityReport *report);
int rasp_security_test_scan_root_mounts_text(const char *text,
                                             RaspSecurityReport *report);
int rasp_security_test_scan_emulator_build_text(const char *text,
                                                RaspSecurityReport *report);
int rasp_security_test_scan_emulator_properties_text(
    const char *text, RaspSecurityReport *report);
int rasp_security_test_scan_emulator_cpuinfo_text(const char *text,
                                                  RaspSecurityReport *report);
int rasp_security_test_apply_runtime_detector_policy(
    RaspSecurityReport *report, const RaspSecurityPolicy *policy);
#endif

#ifdef __cplusplus
}
#endif

#endif
