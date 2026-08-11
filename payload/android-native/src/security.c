#include "rasp_security.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<sys/prctl.h>)
#define RASP_SECURITY_HAS_PRCTL 1
#include <sys/prctl.h>
#endif
#endif

#ifndef RASP_SECURITY_HAS_PRCTL
#define RASP_SECURITY_HAS_PRCTL 0
#endif

#if defined(__has_include)
#if __has_include(<jni.h>)
#define RASP_SECURITY_HAS_JNI 1
#include <jni.h>
#endif
#endif

#ifndef RASP_SECURITY_HAS_JNI
#define RASP_SECURITY_HAS_JNI 0
typedef int jint;
typedef struct JavaVM JavaVM;
#define JNIEXPORT __attribute__((visibility("default")))
#define JNICALL
#define JNI_VERSION_1_6 0x00010006
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RASP_CATEGORY_INSTRUMENTATION "instrumentation"
#define RASP_CATEGORY_DEBUGGER "debugger"
#define RASP_CATEGORY_MEMORY "memory"
#define RASP_CATEGORY_INTEGRITY "integrity"
#define RASP_SECURITY_MAX_PROC_LINES 4096U
#define RASP_SECURITY_MAX_DIRECTORY_ENTRIES 512U
#define RASP_SECURITY_MAX_ENVIRON_BYTES 65536U
#define RASP_SECURITY_MAX_SELF_TEXT_BYTES (2U * 1024U * 1024U)
#define RASP_FNV1A_64_OFFSET 14695981039346656037ULL
#define RASP_FNV1A_64_PRIME 1099511628211ULL

static RaspSecurityReport g_last_report = {
    RASP_SECURITY_DETECTOR_VERSION,
    0U,
    0U,
    RASP_SECURITY_ACTION_ALLOW,
    "no active signals",
    {{0}},
};
static uint64_t g_self_text_checksum = 0U;
static size_t g_self_text_bytes = 0U;
static int g_self_text_checksum_initialized = 0;
static int g_process_hardening_attempted = 0;

static const char *const k_frida_map_tokens[] = {
    "frida",       "gum-js-loop",  "frida-agent", "frida-gadget",
    "linjector",   "re.frida",     "gum-js",      "libfrida",
};

static const char *const k_xposed_tokens[] = {
    "xposed", "lsposed", "edxposed", "sandhook", "yahahfa", "epic",
};

static const char *const k_substrate_tokens[] = {
    "substrate", "cydia_substrate", "libsubstrate",
};

static const char *const k_zygisk_tokens[] = {
    "zygisk", "riru", "magisk",
};

static const char *const k_native_hook_tokens[] = {
    "dobby", "shadowhook", "xhook", "whale", "libhooker", "hookzz",
};

static const char *const k_frida_thread_tokens[] = {
    "frida", "gum-js-loop", "pool-frida", "frida-helper", "frida-agent",
    "frida-dbgsignal", "gum-js",
};

static const char *const k_glib_thread_tokens[] = {
    "gmain", "gdbus",
};

static const char *const k_unix_socket_tokens[] = {
    "frida", "gum-js-loop", "re.frida", "linjector",
};

static const char *const k_environment_tokens[] = {
    "LD_PRELOAD", "frida", "gum-js", "xposed", "zygisk", "substrate",
};

static void rasp_copy_string(char *destination, size_t destination_size,
                             const char *source);
static void rasp_report_add_signal(RaspSecurityReport *report, const char *id,
                                   const char *category, uint8_t confidence,
                                   uint8_t severity, uint8_t weight,
                                   const char *evidence);

static void rasp_report_init(RaspSecurityReport *report) {
  memset(report, 0, sizeof(*report));
  report->detector_version = RASP_SECURITY_DETECTOR_VERSION;
  report->action = RASP_SECURITY_ACTION_ALLOW;
  rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                   "no active signals");
}

static void rasp_copy_string(char *destination, size_t destination_size,
                             const char *source) {
  if (destination_size == 0U) {
    return;
  }
  if (source == NULL) {
    destination[0] = '\0';
    return;
  }
  (void)snprintf(destination, destination_size, "%s", source);
}

static int rasp_ascii_tolower(int value) {
  return tolower((unsigned char)value);
}

static int rasp_contains_case_insensitive(const char *haystack,
                                          const char *needle) {
  size_t haystack_length;
  size_t needle_length;

  if (haystack == NULL || needle == NULL) {
    return 0;
  }

  haystack_length = strlen(haystack);
  needle_length = strlen(needle);
  if (needle_length == 0U || needle_length > haystack_length) {
    return 0;
  }

  for (size_t start = 0U; start + needle_length <= haystack_length; start++) {
    size_t index = 0U;
    while (index < needle_length &&
           rasp_ascii_tolower(haystack[start + index]) ==
               rasp_ascii_tolower(needle[index])) {
      index++;
    }
    if (index == needle_length) {
      return 1;
    }
  }

  return 0;
}

static int rasp_equals_case_insensitive(const char *left, const char *right) {
  size_t left_length;
  size_t right_length;

  if (left == NULL || right == NULL) {
    return 0;
  }

  left_length = strlen(left);
  right_length = strlen(right);
  if (left_length != right_length) {
    return 0;
  }

  for (size_t index = 0U; index < left_length; index++) {
    if (rasp_ascii_tolower(left[index]) != rasp_ascii_tolower(right[index])) {
      return 0;
    }
  }

  return 1;
}

static const char *rasp_first_matching_token(const char *text,
                                             const char *const *tokens,
                                             size_t token_count) {
  for (size_t index = 0U; index < token_count; index++) {
    if (rasp_contains_case_insensitive(text, tokens[index])) {
      return tokens[index];
    }
  }
  return NULL;
}

static uint64_t rasp_fnv1a_update(uint64_t checksum, const unsigned char *bytes,
                                  size_t length) {
  for (size_t index = 0U; index < length; index++) {
    checksum ^= (uint64_t)bytes[index];
    checksum *= RASP_FNV1A_64_PRIME;
  }
  return checksum;
}

static void rasp_harden_process(RaspSecurityReport *report) {
  if (g_process_hardening_attempted) {
    return;
  }
  g_process_hardening_attempted = 1;

#if RASP_SECURITY_HAS_PRCTL && defined(PR_SET_DUMPABLE)
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    rasp_report_add_signal(report, "debugger.dumpable_lock_failed",
                           RASP_CATEGORY_DEBUGGER, 70U, 55U, 20U,
                           "prctl(PR_SET_DUMPABLE)");
  }
#else
  (void)report;
#endif
}

static int rasp_report_has_signal(const RaspSecurityReport *report,
                                  const char *signal_id) {
  for (uint32_t index = 0U; index < report->signal_count; index++) {
    if (strncmp(report->signals[index].id, signal_id,
                RASP_SECURITY_SIGNAL_ID_SIZE) == 0) {
      return 1;
    }
  }
  return 0;
}

static int rasp_parse_maps_range_and_permissions(const char *line,
                                                 unsigned long long *start,
                                                 unsigned long long *end,
                                                 char permissions[5]) {
  if (line == NULL || start == NULL || end == NULL || permissions == NULL) {
    return 0;
  }

  return sscanf(line, "%llx-%llx %4s", start, end, permissions) == 3;
}

static void rasp_report_add_signal(RaspSecurityReport *report, const char *id,
                                   const char *category, uint8_t confidence,
                                   uint8_t severity, uint8_t weight,
                                   const char *evidence) {
  RaspSecuritySignal *signal;
  uint32_t risk_score;

  if (report == NULL || id == NULL || category == NULL ||
      rasp_report_has_signal(report, id) ||
      report->signal_count >= RASP_SECURITY_MAX_SIGNALS) {
    return;
  }

  signal = &report->signals[report->signal_count];
  rasp_copy_string(signal->id, sizeof(signal->id), id);
  rasp_copy_string(signal->category, sizeof(signal->category), category);
  signal->confidence = confidence;
  signal->severity = severity;
  signal->weight = weight;
  rasp_copy_string(signal->evidence, sizeof(signal->evidence), evidence);

  report->signal_count++;

  risk_score = report->risk_score + weight;
  report->risk_score = risk_score > 100U ? 100U : risk_score;
}

RaspSecurityPolicy rasp_security_default_policy(void) {
  RaspSecurityPolicy policy;
  policy.report_threshold = 20U;
  policy.warn_threshold = 40U;
  policy.restrict_threshold = 70U;
  policy.terminate_threshold = 100U;
  policy.runtime_high_risk_action = RASP_SECURITY_ACTION_REPORT;
  policy.startup_integrity_action = RASP_SECURITY_ACTION_TERMINATE;
  policy.startup_payload_tampering_action = RASP_SECURITY_ACTION_TERMINATE;
  return policy;
}

const char *rasp_security_action_name(RaspSecurityAction action) {
  switch (action) {
  case RASP_SECURITY_ACTION_ALLOW:
    return "ALLOW";
  case RASP_SECURITY_ACTION_REPORT:
    return "REPORT";
  case RASP_SECURITY_ACTION_WARN:
    return "WARN";
  case RASP_SECURITY_ACTION_LOCK_STARTUP:
    return "LOCK_STARTUP";
  case RASP_SECURITY_ACTION_TERMINATE:
    return "TERMINATE";
  default:
    return "REPORT";
  }
}

RaspSecurityAction rasp_security_action_from_name(const char *name) {
  if (name == NULL) {
    return RASP_SECURITY_ACTION_REPORT;
  }
  if (rasp_equals_case_insensitive(name, "TERMINATE")) {
    return RASP_SECURITY_ACTION_TERMINATE;
  }
  if (rasp_equals_case_insensitive(name, "LOCK_STARTUP")) {
    return RASP_SECURITY_ACTION_LOCK_STARTUP;
  }
  if (rasp_equals_case_insensitive(name, "WARN")) {
    return RASP_SECURITY_ACTION_WARN;
  }
  if (rasp_equals_case_insensitive(name, "ALLOW")) {
    return RASP_SECURITY_ACTION_ALLOW;
  }
  return RASP_SECURITY_ACTION_REPORT;
}

static int rasp_policy_is_valid(const RaspSecurityPolicy *policy) {
  return policy != NULL && policy->report_threshold <= 100U &&
         policy->warn_threshold <= 100U && policy->restrict_threshold <= 100U &&
         policy->terminate_threshold <= 100U &&
         policy->report_threshold < policy->warn_threshold &&
         policy->warn_threshold < policy->restrict_threshold &&
         policy->restrict_threshold <= policy->terminate_threshold;
}

static int rasp_report_has_startup_integrity_signal(
    const RaspSecurityReport *report) {
  if (report == NULL) {
    return 0;
  }

  for (uint32_t index = 0U; index < report->signal_count; index++) {
    if (strncmp(report->signals[index].id, "startup.", 8U) == 0 &&
        strncmp(report->signals[index].category, RASP_CATEGORY_INTEGRITY,
                RASP_SECURITY_SIGNAL_CATEGORY_SIZE) == 0) {
      return 1;
    }
  }

  return 0;
}

static int rasp_report_has_payload_tampering_signal(
    const RaspSecurityReport *report) {
  if (report == NULL) {
    return 0;
  }

  for (uint32_t index = 0U; index < report->signal_count; index++) {
    if (strncmp(report->signals[index].id, "startup.payload_", 16U) == 0 ||
        strncmp(report->signals[index].id, "startup.protected_asset_", 24U) ==
            0 ||
        strncmp(report->signals[index].id, "runtime.protected_asset_", 24U) ==
            0 ||
        strncmp(report->signals[index].id, "integrity.native_text_modified",
                RASP_SECURITY_SIGNAL_ID_SIZE) ==
            0) {
      return 1;
    }
  }

  return 0;
}

int rasp_security_add_startup_identity_signals(RaspSecurityReport *report,
                                               int package_matches,
                                               int certificate_matches) {
  if (report == NULL) {
    return -1;
  }

  if (!package_matches) {
    rasp_report_add_signal(report, "startup.package_mismatch",
                           RASP_CATEGORY_INTEGRITY, 100U, 100U, 100U,
                           "package name mismatch");
  }

  if (!certificate_matches) {
    rasp_report_add_signal(report, "startup.certificate_mismatch",
                           RASP_CATEGORY_INTEGRITY, 100U, 100U, 100U,
                           "signing certificate mismatch");
  }

  return 0;
}

int rasp_security_add_startup_payload_signals(RaspSecurityReport *report,
                                              int payload_matches,
                                              int protected_assets_match) {
  if (report == NULL) {
    return -1;
  }

  if (!payload_matches) {
    rasp_report_add_signal(report, "startup.payload_integrity_mismatch",
                           RASP_CATEGORY_INTEGRITY, 100U, 100U, 100U,
                           "payload asset digest mismatch");
  }

  if (!protected_assets_match) {
    rasp_report_add_signal(report, "startup.protected_asset_mismatch",
                           RASP_CATEGORY_INTEGRITY, 95U, 90U, 80U,
                           "protected asset digest mismatch");
  }

  return 0;
}

int rasp_security_add_runtime_payload_signals(RaspSecurityReport *report,
                                              int protected_assets_match) {
  if (report == NULL) {
    return -1;
  }

  if (!protected_assets_match) {
    rasp_report_add_signal(report, "runtime.protected_asset_mismatch",
                           RASP_CATEGORY_INTEGRITY, 95U, 90U, 80U,
                           "protected asset digest mismatch");
  }

  return 0;
}

int rasp_security_apply_policy(RaspSecurityReport *report,
                               const RaspSecurityPolicy *policy) {
  RaspSecurityPolicy default_policy;
  const RaspSecurityPolicy *effective_policy;

  if (report == NULL) {
    return -1;
  }

  default_policy = rasp_security_default_policy();
  effective_policy = rasp_policy_is_valid(policy) ? policy : &default_policy;

  if (rasp_report_has_payload_tampering_signal(report)) {
    report->action = effective_policy->startup_payload_tampering_action;
    rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                     "payload integrity mismatch");
    return 0;
  }

  if (rasp_report_has_startup_integrity_signal(report)) {
    report->action = effective_policy->startup_integrity_action;
    rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                     "startup identity integrity mismatch");
    return 0;
  }

  if (report->risk_score < effective_policy->report_threshold ||
      report->signal_count == 0U) {
    report->action = RASP_SECURITY_ACTION_ALLOW;
    rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                     "risk below report threshold");
    return 0;
  }

  if (report->risk_score >= effective_policy->restrict_threshold) {
    report->action = effective_policy->runtime_high_risk_action;
    rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                     "risk reached runtime high-risk threshold");
    return 0;
  }

  if (report->risk_score >= effective_policy->warn_threshold) {
    report->action = RASP_SECURITY_ACTION_WARN;
    rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                     "risk reached warn threshold");
    return 0;
  }

  report->action = RASP_SECURITY_ACTION_REPORT;
  rasp_copy_string(report->action_reason, sizeof(report->action_reason),
                   "risk reached report threshold");
  return 0;
}

static int rasp_maps_line_is_writable_executable(const char *line) {
  const char *permissions;

  if (line == NULL) {
    return 0;
  }

  permissions = strchr(line, ' ');
  if (permissions == NULL) {
    return 0;
  }
  while (*permissions != '\0' && isspace((unsigned char)*permissions)) {
    permissions++;
  }

  if (strlen(permissions) < 3U) {
    return 0;
  }

  return permissions[1] == 'w' && permissions[2] == 'x';
}

static void rasp_scan_maps_line(const char *line, RaspSecurityReport *report) {
  const char *token;

  token = rasp_first_matching_token(
      line, k_frida_map_tokens,
      sizeof(k_frida_map_tokens) / sizeof(k_frida_map_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.frida_library",
                           RASP_CATEGORY_INSTRUMENTATION, 95U, 90U, 45U,
                           token);
  }

  token = rasp_first_matching_token(
      line, k_xposed_tokens, sizeof(k_xposed_tokens) / sizeof(k_xposed_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.xposed_framework",
                           RASP_CATEGORY_INSTRUMENTATION, 90U, 80U, 35U,
                           token);
  }

  token = rasp_first_matching_token(line, k_substrate_tokens,
                                    sizeof(k_substrate_tokens) /
                                        sizeof(k_substrate_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.substrate_framework",
                           RASP_CATEGORY_INSTRUMENTATION, 85U, 75U, 35U,
                           token);
  }

  token = rasp_first_matching_token(
      line, k_zygisk_tokens, sizeof(k_zygisk_tokens) / sizeof(k_zygisk_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.zygisk_module",
                           RASP_CATEGORY_INSTRUMENTATION, 80U, 75U, 35U,
                           token);
  }

  token = rasp_first_matching_token(line, k_native_hook_tokens,
                                    sizeof(k_native_hook_tokens) /
                                        sizeof(k_native_hook_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.native_hook_framework",
                           RASP_CATEGORY_INSTRUMENTATION, 80U, 70U, 35U,
                           token);
  }

  if (rasp_maps_line_is_writable_executable(line)) {
    rasp_report_add_signal(report, "memory.writable_executable_map",
                           RASP_CATEGORY_MEMORY, 55U, 35U, 15U,
                           "rwx mapping");
  }
}

static void rasp_scan_maps_path(const char *path, RaspSecurityReport *report) {
  char line[1024];
  uint32_t lines_read = 0U;
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return;
  }

  while (lines_read < RASP_SECURITY_MAX_PROC_LINES &&
         fgets(line, sizeof(line), file) != NULL) {
    rasp_scan_maps_line(line, report);
    lines_read++;
  }

  (void)fclose(file);
}

static void rasp_trim_newline(char *value) {
  size_t length;

  if (value == NULL) {
    return;
  }

  length = strlen(value);
  while (length > 0U &&
         (value[length - 1U] == '\n' || value[length - 1U] == '\r')) {
    value[length - 1U] = '\0';
    length--;
  }
}

static void rasp_scan_thread_name_value(const char *name,
                                        RaspSecurityReport *report) {
  const char *token;

  token = rasp_first_matching_token(
      name, k_frida_thread_tokens,
      sizeof(k_frida_thread_tokens) / sizeof(k_frida_thread_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.frida_thread",
                           RASP_CATEGORY_INSTRUMENTATION, 90U, 80U, 35U,
                           token);
  }

  token = rasp_first_matching_token(
      name, k_glib_thread_tokens,
      sizeof(k_glib_thread_tokens) / sizeof(k_glib_thread_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.glib_thread",
                           RASP_CATEGORY_INSTRUMENTATION, 65U, 45U, 20U,
                           token);
  }
}

static void rasp_scan_task_threads(const char *task_directory,
                                   RaspSecurityReport *report) {
  DIR *directory;
  struct dirent *entry;
  uint32_t entries_read = 0U;

  directory = opendir(task_directory);
  if (directory == NULL) {
    return;
  }

  while (entries_read < RASP_SECURITY_MAX_DIRECTORY_ENTRIES &&
         (entry = readdir(directory)) != NULL) {
    char path[PATH_MAX];
    char thread_name[128];
    FILE *file;

    entries_read++;

    if (entry->d_name[0] == '.') {
      continue;
    }

    if (snprintf(path, sizeof(path), "%s/%s/comm", task_directory,
                 entry->d_name) >= (int)sizeof(path)) {
      continue;
    }

    file = fopen(path, "r");
    if (file == NULL) {
      continue;
    }

    if (fgets(thread_name, sizeof(thread_name), file) != NULL) {
      rasp_trim_newline(thread_name);
      rasp_scan_thread_name_value(thread_name, report);
    }

    (void)fclose(file);
  }

  (void)closedir(directory);
}

static void rasp_scan_fd_target(const char *target, RaspSecurityReport *report) {
  const char *token;

  token = rasp_first_matching_token(
      target, k_frida_map_tokens,
      sizeof(k_frida_map_tokens) / sizeof(k_frida_map_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.frida_file_descriptor",
                           RASP_CATEGORY_INSTRUMENTATION, 80U, 70U, 25U,
                           token);
  }
}

static void rasp_scan_fd_links(const char *fd_directory,
                               RaspSecurityReport *report) {
  DIR *directory;
  struct dirent *entry;
  uint32_t entries_read = 0U;

  directory = opendir(fd_directory);
  if (directory == NULL) {
    return;
  }

  while (entries_read < RASP_SECURITY_MAX_DIRECTORY_ENTRIES &&
         (entry = readdir(directory)) != NULL) {
    char path[PATH_MAX];
    char target[PATH_MAX];
    ssize_t target_length;

    entries_read++;

    if (entry->d_name[0] == '.') {
      continue;
    }

    if (snprintf(path, sizeof(path), "%s/%s", fd_directory, entry->d_name) >=
        (int)sizeof(path)) {
      continue;
    }

    target_length = readlink(path, target, sizeof(target) - 1U);
    if (target_length <= 0) {
      continue;
    }

    target[target_length] = '\0';
    rasp_scan_fd_target(target, report);
  }

  (void)closedir(directory);
}

static void rasp_scan_status_line(const char *line, RaspSecurityReport *report) {
  static const char tracer_prefix[] = "TracerPid:";
  const char *cursor;
  char *end = NULL;
  long tracer_pid;

  if (line == NULL ||
      strncmp(line, tracer_prefix, sizeof(tracer_prefix) - 1U) != 0) {
    return;
  }

  cursor = line + sizeof(tracer_prefix) - 1U;
  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    cursor++;
  }

  errno = 0;
  tracer_pid = strtol(cursor, &end, 10);
  if (errno == 0 && end != cursor && tracer_pid > 0L) {
    rasp_report_add_signal(report, "debugger.tracer_pid", RASP_CATEGORY_DEBUGGER,
                           95U, 80U, 30U, "TracerPid");
  }
}

static void rasp_scan_status_path(const char *path, RaspSecurityReport *report) {
  char line[256];
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    rasp_scan_status_line(line, report);
  }

  (void)fclose(file);
}

static unsigned long rasp_parse_tcp_local_port(const char *line) {
  const char *cursor;
  const char *local_address;
  const char *colon;

  if (line == NULL) {
    return 0UL;
  }

  cursor = line;
  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    cursor++;
  }
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    cursor++;
  }
  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    cursor++;
  }

  local_address = cursor;
  colon = strchr(local_address, ':');
  if (colon == NULL) {
    return 0UL;
  }

  return strtoul(colon + 1, NULL, 16);
}

static void rasp_scan_tcp_line(const char *line, RaspSecurityReport *report) {
  unsigned long port = rasp_parse_tcp_local_port(line);
  if (port == 27042UL || port == 27043UL) {
    rasp_report_add_signal(report, "instrumentation.frida_default_port",
                           RASP_CATEGORY_INSTRUMENTATION, 50U, 35U, 10U,
                           port == 27042UL ? "tcp:27042" : "tcp:27043");
  }
}

static void rasp_scan_tcp_path(const char *path, RaspSecurityReport *report) {
  char line[512];
  uint32_t lines_read = 0U;
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return;
  }

  while (lines_read < RASP_SECURITY_MAX_PROC_LINES &&
         fgets(line, sizeof(line), file) != NULL) {
    rasp_scan_tcp_line(line, report);
    lines_read++;
  }

  (void)fclose(file);
}

static void rasp_scan_unix_line(const char *line, RaspSecurityReport *report) {
  const char *token = rasp_first_matching_token(
      line, k_unix_socket_tokens,
      sizeof(k_unix_socket_tokens) / sizeof(k_unix_socket_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.frida_unix_socket",
                           RASP_CATEGORY_INSTRUMENTATION, 75U, 65U, 25U,
                           token);
  }
}

static void rasp_scan_unix_path(const char *path, RaspSecurityReport *report) {
  char line[512];
  uint32_t lines_read = 0U;
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return;
  }

  while (lines_read < RASP_SECURITY_MAX_PROC_LINES &&
         fgets(line, sizeof(line), file) != NULL) {
    rasp_scan_unix_line(line, report);
    lines_read++;
  }

  (void)fclose(file);
}

static void rasp_scan_environment_path(const char *path,
                                       RaspSecurityReport *report) {
  char buffer[RASP_SECURITY_MAX_ENVIRON_BYTES];
  FILE *file = fopen(path, "rb");
  size_t bytes_read;
  const char *token;

  if (file == NULL) {
    return;
  }

  bytes_read = fread(buffer, 1U, sizeof(buffer) - 1U, file);
  (void)fclose(file);
  buffer[bytes_read] = '\0';
  for (size_t index = 0U; index < bytes_read; index++) {
    if (buffer[index] == '\0') {
      buffer[index] = '\n';
    }
  }

  token = rasp_first_matching_token(
      buffer, k_environment_tokens,
      sizeof(k_environment_tokens) / sizeof(k_environment_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.suspicious_environment",
                           RASP_CATEGORY_INSTRUMENTATION, 65U, 50U, 25U,
                           token);
  }
}

static int rasp_parse_self_text_maps_line(const char *line,
                                          unsigned long long *start,
                                          unsigned long long *end) {
  char permissions[5] = {0};

  if (!rasp_contains_case_insensitive(line, "libsecurity.so")) {
    return 0;
  }
  if (!rasp_parse_maps_range_and_permissions(line, start, end, permissions)) {
    return 0;
  }

  return permissions[0] == 'r' && permissions[2] == 'x' && *end > *start;
}

static void rasp_scan_self_text_integrity_path(const char *path,
                                               RaspSecurityReport *report) {
  char line[1024];
  uint64_t checksum = RASP_FNV1A_64_OFFSET;
  size_t total_hashed = 0U;
  FILE *file = fopen(path, "r");

  if (file == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), file) != NULL &&
         total_hashed < RASP_SECURITY_MAX_SELF_TEXT_BYTES) {
    unsigned long long start = 0ULL;
    unsigned long long end = 0ULL;
    size_t region_size;
    size_t bytes_to_hash;

    if (!rasp_parse_self_text_maps_line(line, &start, &end)) {
      continue;
    }

    region_size = (size_t)(end - start);
    bytes_to_hash = region_size;
    if (bytes_to_hash > RASP_SECURITY_MAX_SELF_TEXT_BYTES - total_hashed) {
      bytes_to_hash = RASP_SECURITY_MAX_SELF_TEXT_BYTES - total_hashed;
    }
    checksum = rasp_fnv1a_update(checksum, (const unsigned char *)(uintptr_t)start,
                                 bytes_to_hash);
    total_hashed += bytes_to_hash;
  }

  (void)fclose(file);

  if (total_hashed == 0U) {
    return;
  }

  if (!g_self_text_checksum_initialized) {
    g_self_text_checksum = checksum;
    g_self_text_bytes = total_hashed;
    g_self_text_checksum_initialized = 1;
    return;
  }

  if (checksum != g_self_text_checksum || total_hashed != g_self_text_bytes) {
    rasp_report_add_signal(report, "integrity.native_text_modified",
                           RASP_CATEGORY_INTEGRITY, 95U, 90U, 100U,
                           "libsecurity.so text changed");
  }
}

#if RASP_SECURITY_HAS_JNI
static int rasp_jni_find_class(JNIEnv *env, const char *class_name) {
  jclass clazz;

  if (env == NULL || class_name == NULL) {
    return 0;
  }

  clazz = (*env)->FindClass(env, class_name);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
  }
  if (clazz == NULL) {
    return 0;
  }

  (*env)->DeleteLocalRef(env, clazz);
  return 1;
}

static void rasp_scan_java_hook_classes(JNIEnv *env, RaspSecurityReport *report) {
  if (rasp_jni_find_class(env, "de/robv/android/xposed/XposedBridge")) {
    rasp_report_add_signal(report, "instrumentation.xposed_java_class",
                           RASP_CATEGORY_INSTRUMENTATION, 90U, 80U, 35U,
                           "XposedBridge");
  }

  if (rasp_jni_find_class(env, "org/lsposed/lspd/nativebridge/NativeAPI")) {
    rasp_report_add_signal(report, "instrumentation.lsposed_java_class",
                           RASP_CATEGORY_INSTRUMENTATION, 85U, 75U, 30U,
                           "LSPosed NativeAPI");
  }

  if (rasp_jni_find_class(env, "com/saurik/substrate/MS")) {
    rasp_report_add_signal(report, "instrumentation.substrate_java_class",
                           RASP_CATEGORY_INSTRUMENTATION, 80U, 70U, 30U,
                           "Substrate MS");
  }
}

static uint8_t rasp_threshold_from_jint(jint value, uint8_t fallback) {
  if (value < 0 || value > 100) {
    return fallback;
  }
  return (uint8_t)value;
}

static RaspSecurityPolicy rasp_policy_from_jni_args(
    JNIEnv *env, jint report_threshold, jint warn_threshold,
    jint restrict_threshold, jint terminate_threshold,
    jstring runtime_high_risk_action, jstring startup_integrity_action,
    jstring startup_payload_tampering_action) {
  RaspSecurityPolicy defaults = rasp_security_default_policy();
  RaspSecurityPolicy policy = defaults;
  const char *action_chars = NULL;

  policy.report_threshold =
      rasp_threshold_from_jint(report_threshold, defaults.report_threshold);
  policy.warn_threshold =
      rasp_threshold_from_jint(warn_threshold, defaults.warn_threshold);
  policy.restrict_threshold =
      rasp_threshold_from_jint(restrict_threshold, defaults.restrict_threshold);
  policy.terminate_threshold =
      rasp_threshold_from_jint(terminate_threshold, defaults.terminate_threshold);

  if (runtime_high_risk_action != NULL) {
    action_chars =
        (*env)->GetStringUTFChars(env, runtime_high_risk_action, NULL);
    if (action_chars != NULL) {
      policy.runtime_high_risk_action =
          rasp_security_action_from_name(action_chars);
      (*env)->ReleaseStringUTFChars(env, runtime_high_risk_action, action_chars);
    }
  }

  if (startup_integrity_action != NULL) {
    action_chars = (*env)->GetStringUTFChars(env, startup_integrity_action, NULL);
    if (action_chars != NULL) {
      policy.startup_integrity_action =
          rasp_security_action_from_name(action_chars);
      (*env)->ReleaseStringUTFChars(env, startup_integrity_action, action_chars);
    }
  }

  if (startup_payload_tampering_action != NULL) {
    action_chars =
        (*env)->GetStringUTFChars(env, startup_payload_tampering_action, NULL);
    if (action_chars != NULL) {
      policy.startup_payload_tampering_action =
          rasp_security_action_from_name(action_chars);
      (*env)->ReleaseStringUTFChars(env, startup_payload_tampering_action,
                                    action_chars);
    }
  }

  if (!rasp_policy_is_valid(&policy)) {
    return defaults;
  }

  return policy;
}
#endif

static void rasp_set_last_report(const RaspSecurityReport *report) {
  if (report == NULL) {
    rasp_report_init(&g_last_report);
    return;
  }
  g_last_report = *report;
}

int rasp_security_collect(RaspSecurityReport *report) {
  if (report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  rasp_harden_process(report);
  rasp_scan_maps_path("/proc/self/maps", report);
  rasp_scan_self_text_integrity_path("/proc/self/maps", report);
  rasp_scan_status_path("/proc/self/status", report);
  rasp_scan_task_threads("/proc/self/task", report);
  rasp_scan_fd_links("/proc/self/fd", report);
  rasp_scan_tcp_path("/proc/net/tcp", report);
  rasp_scan_tcp_path("/proc/net/tcp6", report);
  rasp_scan_unix_path("/proc/net/unix", report);
  rasp_scan_environment_path("/proc/self/environ", report);
  (void)rasp_security_apply_policy(report, NULL);

  return 0;
}

__attribute__((visibility("default"))) int rasp_security_initialize(void) {
  RaspSecurityReport report;
  if (rasp_security_collect(&report) != 0) {
    rasp_report_init(&report);
  }
  rasp_set_last_report(&report);
  return 0;
}

const RaspSecurityReport *rasp_security_last_report(void) {
  return &g_last_report;
}

static void rasp_json_append(char **cursor, size_t *remaining, const char *value) {
  size_t length;
  size_t copy_length;

  if (cursor == NULL || remaining == NULL || value == NULL ||
      *remaining == 0U) {
    return;
  }

  length = strlen(value);
  copy_length = length < (*remaining - 1U) ? length : (*remaining - 1U);
  if (copy_length > 0U) {
    memcpy(*cursor, value, copy_length);
    *cursor += copy_length;
    *remaining -= copy_length;
  }
  **cursor = '\0';
}

static void rasp_json_append_format(char **cursor, size_t *remaining,
                                    const char *format, ...) {
  va_list arguments;
  char scratch[64];
  int written;

  if (format == NULL) {
    return;
  }

  va_start(arguments, format);
  written = vsnprintf(scratch, sizeof(scratch), format, arguments);
  va_end(arguments);

  if (written <= 0) {
    return;
  }

  rasp_json_append(cursor, remaining, scratch);
}

static void rasp_json_append_escaped(char **cursor, size_t *remaining,
                                     const char *value) {
  char escape[7];

  rasp_json_append(cursor, remaining, "\"");
  if (value != NULL) {
    for (const unsigned char *current = (const unsigned char *)value;
         *current != '\0'; current++) {
      if (*current == '"' || *current == '\\') {
        escape[0] = '\\';
        escape[1] = (char)*current;
        escape[2] = '\0';
        rasp_json_append(cursor, remaining, escape);
      } else if (*current < 0x20U) {
        (void)snprintf(escape, sizeof(escape), "\\u%04x", *current);
        rasp_json_append(cursor, remaining, escape);
      } else {
        char single[2] = {(char)*current, '\0'};
        rasp_json_append(cursor, remaining, single);
      }
    }
  }
  rasp_json_append(cursor, remaining, "\"");
}

size_t rasp_security_report_to_json(const RaspSecurityReport *report, char *buffer,
                                    size_t buffer_size) {
  char *cursor = buffer;
  size_t remaining = buffer_size;

  if (buffer == NULL || buffer_size == 0U) {
    return 0U;
  }

  buffer[0] = '\0';
  if (report == NULL) {
    rasp_json_append(&cursor, &remaining, "{}");
    return strlen(buffer);
  }

  rasp_json_append(&cursor, &remaining, "{\"detector_version\":");
  rasp_json_append_format(&cursor, &remaining, "%u", report->detector_version);
  rasp_json_append(&cursor, &remaining, ",\"risk_score\":");
  rasp_json_append_format(&cursor, &remaining, "%u", report->risk_score);
  rasp_json_append(&cursor, &remaining, ",\"action\":");
  rasp_json_append_escaped(&cursor, &remaining,
                           rasp_security_action_name(report->action));
  rasp_json_append(&cursor, &remaining, ",\"action_reason\":");
  rasp_json_append_escaped(&cursor, &remaining, report->action_reason);
  rasp_json_append(&cursor, &remaining, ",\"signals\":[");

  for (uint32_t index = 0U; index < report->signal_count; index++) {
    const RaspSecuritySignal *signal = &report->signals[index];
    if (index > 0U) {
      rasp_json_append(&cursor, &remaining, ",");
    }
    rasp_json_append(&cursor, &remaining, "{\"id\":");
    rasp_json_append_escaped(&cursor, &remaining, signal->id);
    rasp_json_append(&cursor, &remaining, ",\"category\":");
    rasp_json_append_escaped(&cursor, &remaining, signal->category);
    rasp_json_append(&cursor, &remaining, ",\"confidence\":");
    rasp_json_append_format(&cursor, &remaining, "%u", signal->confidence);
    rasp_json_append(&cursor, &remaining, ",\"severity\":");
    rasp_json_append_format(&cursor, &remaining, "%u", signal->severity);
    rasp_json_append(&cursor, &remaining, ",\"weight\":");
    rasp_json_append_format(&cursor, &remaining, "%u", signal->weight);
    rasp_json_append(&cursor, &remaining, ",\"evidence\":");
    rasp_json_append_escaped(&cursor, &remaining, signal->evidence);
    rasp_json_append(&cursor, &remaining, "}");
  }

  rasp_json_append(&cursor, &remaining, "]}");
  return strlen(buffer);
}

size_t rasp_security_last_report_json(char *buffer, size_t buffer_size) {
  return rasp_security_report_to_json(&g_last_report, buffer, buffer_size);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)vm;
  (void)reserved;
  return JNI_VERSION_1_6;
}

#if RASP_SECURITY_HAS_JNI
static void rasp_enforce_terminal_action(const RaspSecurityReport *report) {
  if (report == NULL) {
    return;
  }
  if (report->action != RASP_SECURITY_ACTION_TERMINATE &&
      report->action != RASP_SECURITY_ACTION_LOCK_STARTUP) {
    return;
  }

  (void)kill(getpid(), SIGKILL);
  _exit(10);
}

JNIEXPORT jint JNICALL
Java_com_rasp_runtime_bootstrap_RaspInitProvider_nativeInitialize(
    JNIEnv *env, jclass clazz, jobject context, jint report_threshold,
    jint warn_threshold, jint restrict_threshold, jint terminate_threshold,
    jstring runtime_high_risk_action, jstring startup_integrity_action,
    jstring startup_payload_tampering_action, jint package_matches,
    jint certificate_matches, jint payload_matches,
    jint protected_assets_match) {
  RaspSecurityReport report;
  RaspSecurityPolicy policy;
  (void)clazz;
  (void)context;

  if (rasp_security_collect(&report) != 0) {
    rasp_report_init(&report);
  }
  rasp_scan_java_hook_classes(env, &report);
  (void)rasp_security_add_startup_identity_signals(
      &report, package_matches != 0, certificate_matches != 0);
  (void)rasp_security_add_startup_payload_signals(
      &report, payload_matches != 0, protected_assets_match != 0);
  policy = rasp_policy_from_jni_args(env, report_threshold, warn_threshold,
                                     restrict_threshold, terminate_threshold,
                                     runtime_high_risk_action,
                                     startup_integrity_action,
                                     startup_payload_tampering_action);
  (void)rasp_security_apply_policy(&report, &policy);
  rasp_set_last_report(&report);
  rasp_enforce_terminal_action(&report);

  return (jint)report.risk_score;
}

JNIEXPORT jint JNICALL
Java_com_rasp_runtime_bootstrap_RaspInitProvider_nativeLastActionCode(
    JNIEnv *env, jclass clazz) {
  (void)env;
  (void)clazz;
  return (jint)g_last_report.action;
}

JNIEXPORT jint JNICALL
Java_com_rasp_runtime_bootstrap_RaspInitProvider_nativeMonitorScan(
    JNIEnv *env, jclass clazz, jint report_threshold, jint warn_threshold,
    jint restrict_threshold, jint terminate_threshold,
    jstring runtime_high_risk_action, jstring startup_payload_tampering_action,
    jint protected_assets_match) {
  RaspSecurityReport report;
  RaspSecurityPolicy policy;
  (void)clazz;

  if (rasp_security_collect(&report) != 0) {
    rasp_report_init(&report);
  }

  rasp_scan_java_hook_classes(env, &report);
  (void)rasp_security_add_runtime_payload_signals(
      &report, protected_assets_match != 0);
  policy = rasp_policy_from_jni_args(env, report_threshold, warn_threshold,
                                     restrict_threshold, terminate_threshold,
                                     runtime_high_risk_action, NULL,
                                     startup_payload_tampering_action);
  (void)rasp_security_apply_policy(&report, &policy);
  rasp_set_last_report(&report);
  rasp_enforce_terminal_action(&report);

  return (jint)report.risk_score;
}

JNIEXPORT jstring JNICALL
Java_com_rasp_runtime_bootstrap_RaspInitProvider_nativeLastReportJson(
    JNIEnv *env, jclass clazz) {
  char buffer[RASP_SECURITY_REPORT_JSON_SIZE];
  (void)clazz;

  (void)rasp_security_last_report_json(buffer, sizeof(buffer));
  return (*env)->NewStringUTF(env, buffer);
}
#endif

#ifdef RASP_SECURITY_TEST
int rasp_security_test_scan_maps_text(const char *text, RaspSecurityReport *report) {
  const char *line_start;

  if (text == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  line_start = text;
  while (*line_start != '\0') {
    char line[1024];
    size_t length = 0U;
    while (line_start[length] != '\0' && line_start[length] != '\n' &&
           length + 1U < sizeof(line)) {
      length++;
    }
    memcpy(line, line_start, length);
    line[length] = '\0';
    rasp_scan_maps_line(line, report);
    line_start += length;
    if (*line_start == '\n') {
      line_start++;
    }
  }

  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}

int rasp_security_test_scan_status_text(const char *text,
                                        RaspSecurityReport *report) {
  const char *line_start;

  if (text == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  line_start = text;
  while (*line_start != '\0') {
    char line[256];
    size_t length = 0U;
    while (line_start[length] != '\0' && line_start[length] != '\n' &&
           length + 1U < sizeof(line)) {
      length++;
    }
    memcpy(line, line_start, length);
    line[length] = '\0';
    rasp_scan_status_line(line, report);
    line_start += length;
    if (*line_start == '\n') {
      line_start++;
    }
  }

  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}

int rasp_security_test_scan_thread_name(const char *name,
                                        RaspSecurityReport *report) {
  if (name == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  rasp_scan_thread_name_value(name, report);
  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}

int rasp_security_test_scan_tcp_text(const char *text, RaspSecurityReport *report) {
  const char *line_start;

  if (text == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  line_start = text;
  while (*line_start != '\0') {
    char line[512];
    size_t length = 0U;
    while (line_start[length] != '\0' && line_start[length] != '\n' &&
           length + 1U < sizeof(line)) {
      length++;
    }
    memcpy(line, line_start, length);
    line[length] = '\0';
    rasp_scan_tcp_line(line, report);
    line_start += length;
    if (*line_start == '\n') {
      line_start++;
    }
  }

  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}

int rasp_security_test_scan_unix_text(const char *text,
                                      RaspSecurityReport *report) {
  const char *line_start;

  if (text == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  line_start = text;
  while (*line_start != '\0') {
    char line[512];
    size_t length = 0U;
    while (line_start[length] != '\0' && line_start[length] != '\n' &&
           length + 1U < sizeof(line)) {
      length++;
    }
    memcpy(line, line_start, length);
    line[length] = '\0';
    rasp_scan_unix_line(line, report);
    line_start += length;
    if (*line_start == '\n') {
      line_start++;
    }
  }

  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}

int rasp_security_test_scan_environment_text(const char *text,
                                             RaspSecurityReport *report) {
  const char *token;

  if (text == NULL || report == NULL) {
    return -1;
  }

  rasp_report_init(report);
  token = rasp_first_matching_token(
      text, k_environment_tokens,
      sizeof(k_environment_tokens) / sizeof(k_environment_tokens[0]));
  if (token != NULL) {
    rasp_report_add_signal(report, "instrumentation.suspicious_environment",
                           RASP_CATEGORY_INSTRUMENTATION, 65U, 50U, 25U,
                           token);
  }
  (void)rasp_security_apply_policy(report, NULL);
  return 0;
}
#endif
