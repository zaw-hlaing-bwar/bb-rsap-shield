package com.rasp.runtime.bootstrap;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONArray;
import org.json.JSONObject;

public final class RaspInitProvider extends ContentProvider {
  private static final String TAG = "RaspShield";
  private static final String INTEGRITY_MANIFEST_ASSET =
      "rasp-shield/integrity-manifest.json";
  private static final int ACTION_ALLOW = 0;
  private static final int ACTION_REPORT = 1;
  private static final int ACTION_WARN = 2;
  private static final int ACTION_LOCK_STARTUP = 3;
  private static final int ACTION_TERMINATE = 4;
  private static final long MAX_STARTUP_JAVASCRIPT_HASH_BYTES = 2L * 1024L * 1024L;
  private static final int MIN_MONITOR_INTERVAL_MS = 1000;
  private static final int MAX_MONITOR_INTERVAL_MS = 10 * 60 * 1000;

  private static volatile boolean nativeLibraryLoaded;
  private static volatile boolean initialized;
  private static volatile boolean monitorStarted;
  private static volatile boolean lifecycleRegistered;
  private static volatile int activeActivities;
  private static volatile int lastRiskScore;
  private static volatile int lastAction = ACTION_ALLOW;
  private static volatile String lastActionName = "ALLOW";
  private static volatile String lastReportJson = "{}";
  private static volatile long lastStartupDurationMs;
  private static volatile boolean lastStartupBudgetExceeded;

  static {
    try {
      System.loadLibrary("security");
      nativeLibraryLoaded = true;
    } catch (Throwable ignored) {
      nativeLibraryLoaded = false;
    }
  }

  private static native int nativeInitialize(Context context, int reportThreshold,
      int warnThreshold, int restrictThreshold, int terminateThreshold,
      String runtimeHighRiskAction, String startupIntegrityAction,
      String startupPayloadTamperingAction, int packageMatches,
      int certificateMatches, int payloadMatches, int protectedAssetsMatch,
      int debuggerDetectionEnabled, int debuggerDetectionWeight,
      int instrumentationDetectionEnabled, int instrumentationDetectionWeight,
      int memoryIntegrityEnabled, int memoryIntegrityWeight,
      int rootDetectionEnabled, int rootDetectionWeight,
      int emulatorDetectionEnabled, int emulatorDetectionWeight);

  private static native int nativeMonitorScan(int reportThreshold,
      int warnThreshold, int restrictThreshold, int terminateThreshold,
      String runtimeHighRiskAction, String startupPayloadTamperingAction,
      int protectedAssetsMatch, int debuggerDetectionEnabled,
      int debuggerDetectionWeight, int instrumentationDetectionEnabled,
      int instrumentationDetectionWeight, int memoryIntegrityEnabled,
      int memoryIntegrityWeight, int rootDetectionEnabled, int rootDetectionWeight,
      int emulatorDetectionEnabled, int emulatorDetectionWeight);

  private static native int nativeLastActionCode();

  private static native String nativeLastReportJson();

  public static boolean isInitialized() {
    return initialized;
  }

  public static int getLastRiskScore() {
    return lastRiskScore;
  }

  public static int getLastAction() {
    return lastAction;
  }

  public static String getLastActionName() {
    return lastActionName;
  }

  public static String getLastReportJson() {
    return lastReportJson;
  }

  public static long getLastStartupDurationMs() {
    return lastStartupDurationMs;
  }

  public static boolean isLastStartupBudgetExceeded() {
    return lastStartupBudgetExceeded;
  }

  @Override
  public boolean onCreate() {
    long startupStartNs = SystemClock.elapsedRealtimeNanos();
    RuntimePolicy policyForMonitor = RuntimePolicy.defaults();
    if (!nativeLibraryLoaded) {
      recordStartupTiming(startupStartNs, policyForMonitor, false, ACTION_ALLOW);
      return true;
    }

    int actionToApply = ACTION_ALLOW;
    try {
      Context context = getContext();
      Context applicationContext =
          context == null ? null : context.getApplicationContext();
      RuntimePolicy policy = RuntimePolicy.load(applicationContext);
      policyForMonitor = policy;
      boolean packageMatches = policy.packageMatches(applicationContext);
      boolean certificateMatches = policy.certificateMatches(applicationContext);
      boolean payloadMatches = policy.payloadAssetsMatch(applicationContext);
      boolean protectedAssetsMatch =
          policy.smallProtectedAssetsMatch(applicationContext);
      lastRiskScore = nativeInitialize(applicationContext, policy.reportThreshold,
          policy.warnThreshold, policy.restrictThreshold, policy.terminateThreshold,
          policy.runtimeHighRiskAction, policy.startupIntegrityAction,
          policy.startupPayloadTamperingAction, packageMatches ? 1 : 0,
          certificateMatches ? 1 : 0, payloadMatches ? 1 : 0,
          protectedAssetsMatch ? 1 : 0,
          policy.debuggerDetectionEnabled ? 1 : 0,
          policy.debuggerDetectionWeight,
          policy.instrumentationDetectionEnabled ? 1 : 0,
          policy.instrumentationDetectionWeight,
          policy.memoryIntegrityEnabled ? 1 : 0, policy.memoryIntegrityWeight,
          policy.rootDetectionEnabled ? 1 : 0,
          policy.rootDetectionWeight, policy.emulatorDetectionEnabled ? 1 : 0,
          policy.emulatorDetectionWeight);
      refreshLastNativeReport();
      actionToApply = lastAction;
      initialized = true;
    } catch (Throwable ignored) {
      initialized = false;
    }

    recordStartupTiming(startupStartNs, policyForMonitor, initialized, actionToApply);
    applyAction(actionToApply);
    if (initialized && policyForMonitor != null) {
      startMonitoring(applicationContext(), policyForMonitor);
    }
    return true;
  }

  private static void recordStartupTiming(long startupStartNs, RuntimePolicy policy,
      boolean startupInitialized, int action) {
    long elapsedNs = SystemClock.elapsedRealtimeNanos() - startupStartNs;
    long durationMs = Math.max(0L, elapsedNs / 1000000L);
    if (elapsedNs > 0L && elapsedNs % 1000000L != 0L) {
      durationMs++;
    }

    int budgetMs = policy == null
        ? RuntimePolicy.defaults().startupBudgetMs
        : policy.startupBudgetMs;
    boolean budgetExceeded = durationMs > budgetMs;
    lastStartupDurationMs = durationMs;
    lastStartupBudgetExceeded = budgetExceeded;

    String message = "startup_duration_ms=" + durationMs
        + " startup_budget_ms=" + budgetMs
        + " startup_budget_exceeded=" + budgetExceeded
        + " initialized=" + startupInitialized
        + " action=" + actionName(action);
    if (budgetExceeded) {
      Log.w(TAG, message);
    } else {
      Log.i(TAG, message);
    }
  }

  private Context applicationContext() {
    Context context = getContext();
    return context == null ? null : context.getApplicationContext();
  }

  private static void applyAction(int action) {
    if (action == ACTION_LOCK_STARTUP) {
      throw new IllegalStateException("RASP Shield locked startup");
    }
    if (action == ACTION_TERMINATE) {
      android.os.Process.killProcess(android.os.Process.myPid());
      System.exit(10);
    }
  }

  private static void applyRuntimeAction(int action) {
    if (action == ACTION_TERMINATE || action == ACTION_LOCK_STARTUP) {
      android.os.Process.killProcess(android.os.Process.myPid());
      System.exit(10);
    }
  }

  private static void refreshLastNativeReport() {
    lastAction = nativeLastActionCode();
    lastActionName = actionName(lastAction);
    String report = nativeLastReportJson();
    if (report != null) {
      lastReportJson = report;
    }
  }

  private static void startMonitoring(Context context, final RuntimePolicy policy) {
    if (policy == null || !policy.monitoringEnabled) {
      return;
    }

    synchronized (RaspInitProvider.class) {
      if (monitorStarted) {
        return;
      }
      monitorStarted = true;
    }

    registerLifecycleCallbacks(context);
    Thread monitor = new Thread(new Runnable() {
      @Override
      public void run() {
        runMonitorLoop(context, policy);
      }
    }, "RaspShieldMonitor");
    monitor.setDaemon(true);
    monitor.start();
  }

  private static void runMonitorLoop(Context context, RuntimePolicy policy) {
    while (true) {
      if (!sleepQuietly(policy.nextScanDelayMs())) {
        return;
      }
      if (!shouldMonitorNow(policy)) {
        continue;
      }

      int actionToApply = ACTION_ALLOW;
      try {
        boolean protectedAssetsMatch =
            policy.nextRuntimeProtectedAssetMatches(context);
        lastRiskScore = nativeMonitorScan(policy.reportThreshold,
            policy.warnThreshold, policy.restrictThreshold, policy.terminateThreshold,
            policy.runtimeHighRiskAction, policy.startupPayloadTamperingAction,
            protectedAssetsMatch ? 1 : 0,
            policy.debuggerDetectionEnabled ? 1 : 0,
            policy.debuggerDetectionWeight,
            policy.instrumentationDetectionEnabled ? 1 : 0,
            policy.instrumentationDetectionWeight,
            policy.memoryIntegrityEnabled ? 1 : 0, policy.memoryIntegrityWeight,
            policy.rootDetectionEnabled ? 1 : 0,
            policy.rootDetectionWeight, policy.emulatorDetectionEnabled ? 1 : 0,
            policy.emulatorDetectionWeight);
        refreshLastNativeReport();
        actionToApply = lastAction;

        if (policy.deepScanOnSuspicion && actionToApply != ACTION_ALLOW) {
          boolean deepProtectedAssetsMatch = protectedAssetsMatch
              && policy.allRuntimeProtectedAssetsMatch(context);
          lastRiskScore = nativeMonitorScan(policy.reportThreshold,
              policy.warnThreshold, policy.restrictThreshold,
              policy.terminateThreshold, policy.runtimeHighRiskAction,
              policy.startupPayloadTamperingAction,
              deepProtectedAssetsMatch ? 1 : 0,
              policy.debuggerDetectionEnabled ? 1 : 0,
              policy.debuggerDetectionWeight,
              policy.instrumentationDetectionEnabled ? 1 : 0,
              policy.instrumentationDetectionWeight,
              policy.memoryIntegrityEnabled ? 1 : 0, policy.memoryIntegrityWeight,
              policy.rootDetectionEnabled ? 1 : 0, policy.rootDetectionWeight,
              policy.emulatorDetectionEnabled ? 1 : 0,
              policy.emulatorDetectionWeight);
          refreshLastNativeReport();
          actionToApply = lastAction;
        }
      } catch (Throwable ignored) {
        actionToApply = ACTION_ALLOW;
      }

      applyRuntimeAction(actionToApply);
    }
  }

  private static void registerLifecycleCallbacks(Context context) {
    if (lifecycleRegistered || !(context instanceof Application)) {
      return;
    }

    synchronized (RaspInitProvider.class) {
      if (lifecycleRegistered || !(context instanceof Application)) {
        return;
      }
      ((Application) context).registerActivityLifecycleCallbacks(
          new Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            }

            @Override
            public void onActivityStarted(Activity activity) {
              activeActivities++;
            }

            @Override
            public void onActivityResumed(Activity activity) {
            }

            @Override
            public void onActivityPaused(Activity activity) {
            }

            @Override
            public void onActivityStopped(Activity activity) {
              if (activeActivities > 0) {
                activeActivities--;
              }
            }

            @Override
            public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            }

            @Override
            public void onActivityDestroyed(Activity activity) {
            }
          });
      lifecycleRegistered = true;
    }
  }

  private static boolean shouldMonitorNow(RuntimePolicy policy) {
    return policy.monitorBackgroundState || !lifecycleRegistered || activeActivities > 0;
  }

  private static boolean sleepQuietly(int delayMs) {
    try {
      Thread.sleep(delayMs);
      return true;
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  private static String actionName(int action) {
    switch (action) {
      case ACTION_REPORT:
        return "REPORT";
      case ACTION_WARN:
        return "WARN";
      case ACTION_LOCK_STARTUP:
        return "LOCK_STARTUP";
      case ACTION_TERMINATE:
        return "TERMINATE";
      case ACTION_ALLOW:
      default:
        return "ALLOW";
    }
  }

  private static final class RuntimePolicy {
    private final int reportThreshold;
    private final int warnThreshold;
    private final int restrictThreshold;
    private final int terminateThreshold;
    private final int startupBudgetMs;
    private final String runtimeHighRiskAction;
    private final String startupIntegrityAction;
    private final String startupPayloadTamperingAction;
    private final boolean monitoringEnabled;
    private final int scanIntervalMinimumMs;
    private final int scanIntervalMaximumMs;
    private final boolean deepScanOnSuspicion;
    private final boolean monitorBackgroundState;
    private final boolean debuggerDetectionEnabled;
    private final int debuggerDetectionWeight;
    private final boolean instrumentationDetectionEnabled;
    private final int instrumentationDetectionWeight;
    private final boolean memoryIntegrityEnabled;
    private final int memoryIntegrityWeight;
    private final boolean rootDetectionEnabled;
    private final int rootDetectionWeight;
    private final boolean emulatorDetectionEnabled;
    private final int emulatorDetectionWeight;
    private final String expectedPackageName;
    private final List<String> expectedCertificateSha256;
    private final List<ProtectedAsset> protectedAssets;
    private final int expectedEntryCount;
    private final String expectedEntrySetSha256;
    private final int expectedExecutableEntryCount;
    private final String expectedExecutableEntrySetSha256;
    private final boolean manifestLoaded;
    private int nextRuntimeProtectedAssetIndex;

    private RuntimePolicy(int reportThreshold, int warnThreshold,
        int restrictThreshold, int terminateThreshold, int startupBudgetMs,
        String runtimeHighRiskAction, String startupIntegrityAction,
        String startupPayloadTamperingAction, boolean monitoringEnabled,
        int scanIntervalMinimumMs,
        int scanIntervalMaximumMs, boolean deepScanOnSuspicion,
        boolean monitorBackgroundState, boolean debuggerDetectionEnabled,
        int debuggerDetectionWeight, boolean instrumentationDetectionEnabled,
        int instrumentationDetectionWeight, boolean memoryIntegrityEnabled,
        int memoryIntegrityWeight, boolean rootDetectionEnabled,
        int rootDetectionWeight, boolean emulatorDetectionEnabled,
        int emulatorDetectionWeight,
        String expectedPackageName, List<String> expectedCertificateSha256,
        List<ProtectedAsset> protectedAssets, int expectedEntryCount,
        String expectedEntrySetSha256, int expectedExecutableEntryCount,
        String expectedExecutableEntrySetSha256, boolean manifestLoaded) {
      this.reportThreshold = reportThreshold;
      this.warnThreshold = warnThreshold;
      this.restrictThreshold = restrictThreshold;
      this.terminateThreshold = terminateThreshold;
      this.startupBudgetMs = startupBudgetMs;
      this.runtimeHighRiskAction = runtimeHighRiskAction;
      this.startupIntegrityAction = startupIntegrityAction;
      this.startupPayloadTamperingAction = startupPayloadTamperingAction;
      this.monitoringEnabled = monitoringEnabled;
      this.scanIntervalMinimumMs = clampInterval(scanIntervalMinimumMs);
      this.scanIntervalMaximumMs = clampInterval(scanIntervalMaximumMs);
      this.deepScanOnSuspicion = deepScanOnSuspicion;
      this.monitorBackgroundState = monitorBackgroundState;
      this.debuggerDetectionEnabled = debuggerDetectionEnabled;
      this.debuggerDetectionWeight = debuggerDetectionWeight;
      this.instrumentationDetectionEnabled = instrumentationDetectionEnabled;
      this.instrumentationDetectionWeight = instrumentationDetectionWeight;
      this.memoryIntegrityEnabled = memoryIntegrityEnabled;
      this.memoryIntegrityWeight = memoryIntegrityWeight;
      this.rootDetectionEnabled = rootDetectionEnabled;
      this.rootDetectionWeight = rootDetectionWeight;
      this.emulatorDetectionEnabled = emulatorDetectionEnabled;
      this.emulatorDetectionWeight = emulatorDetectionWeight;
      this.expectedPackageName = expectedPackageName;
      this.expectedCertificateSha256 = expectedCertificateSha256;
      this.protectedAssets = protectedAssets;
      this.expectedEntryCount = expectedEntryCount;
      this.expectedEntrySetSha256 = expectedEntrySetSha256;
      this.expectedExecutableEntryCount = expectedExecutableEntryCount;
      this.expectedExecutableEntrySetSha256 = expectedExecutableEntrySetSha256;
      this.manifestLoaded = manifestLoaded;
    }

    private static RuntimePolicy defaults() {
      return new RuntimePolicy(20, 40, 70, 100, 50, "REPORT", "TERMINATE",
          "TERMINATE", true, 5000, 15000, true, false, true, 40, true, 60,
          true, 60, true, 20, false, 10, "", new ArrayList<String>(),
          new ArrayList<ProtectedAsset>(), 0, "", 0, "", false);
    }

    private static RuntimePolicy load(Context context) {
      if (context == null) {
        return defaults();
      }

      try {
        JSONObject root = new JSONObject(readAsset(context, INTEGRITY_MANIFEST_ASSET));
        JSONObject application = root.optJSONObject("application");
        JSONObject android = root.optJSONObject("android");
        JSONObject policy = root.optJSONObject("policy");
        JSONObject runtime = policy == null ? null : policy.optJSONObject("runtime");
        JSONObject monitoring = runtime == null ? null : runtime.optJSONObject("monitoring");
        JSONObject detections = runtime == null ? null : runtime.optJSONObject("detections");
        JSONObject apkInventory = root.optJSONObject("apk_inventory");
        JSONArray protectedAssets = root.optJSONArray("protected_assets");
        JSONObject thresholds =
            runtime == null ? null : runtime.optJSONObject("thresholds");
        RuntimePolicy defaults = defaults();
        RuntimePolicy parsed = new RuntimePolicy(
            optRiskScore(thresholds, "report", defaults.reportThreshold),
            optRiskScore(thresholds, "warn", defaults.warnThreshold),
            optRiskScore(thresholds, "restrict", defaults.restrictThreshold),
            optRiskScore(thresholds, "terminate", defaults.terminateThreshold),
            runtime == null
                ? defaults.startupBudgetMs
                : runtime.optInt("startup_budget_ms", defaults.startupBudgetMs),
            runtime == null
                ? defaults.runtimeHighRiskAction
                : runtime.optString("runtime_high_risk_action",
                    defaults.runtimeHighRiskAction),
            runtime == null
                ? defaults.startupIntegrityAction
                : runtime.optString("startup_integrity_action",
                    defaults.startupIntegrityAction),
            runtime == null
                ? defaults.startupPayloadTamperingAction
                : runtime.optString("startup_payload_tampering_action",
                    defaults.startupPayloadTamperingAction),
            monitoring == null
                ? defaults.monitoringEnabled
                : monitoring.optBoolean("enabled", defaults.monitoringEnabled),
            monitoring == null
                ? defaults.scanIntervalMinimumMs
                : monitoring.optInt("scan_interval_minimum_ms",
                    defaults.scanIntervalMinimumMs),
            monitoring == null
                ? defaults.scanIntervalMaximumMs
                : monitoring.optInt("scan_interval_maximum_ms",
                    defaults.scanIntervalMaximumMs),
            monitoring == null
                ? defaults.deepScanOnSuspicion
                : monitoring.optBoolean("deep_scan_on_suspicion",
                    defaults.deepScanOnSuspicion),
            monitoring == null
                ? defaults.monitorBackgroundState
                : monitoring.optBoolean("monitor_background_state",
                    defaults.monitorBackgroundState),
            optDetectionEnabled(detections, "debugger",
                defaults.debuggerDetectionEnabled),
            optDetectionWeight(detections, "debugger",
                defaults.debuggerDetectionWeight),
            optDetectionEnabled(detections, "instrumentation",
                defaults.instrumentationDetectionEnabled),
            optDetectionWeight(detections, "instrumentation",
                defaults.instrumentationDetectionWeight),
            optDetectionEnabled(detections, "memory",
                defaults.memoryIntegrityEnabled),
            optDetectionWeight(detections, "memory",
                defaults.memoryIntegrityWeight),
            optDetectionEnabled(detections, "root",
                defaults.rootDetectionEnabled),
            optDetectionWeight(detections, "root", defaults.rootDetectionWeight),
            optDetectionEnabled(detections, "emulator",
                defaults.emulatorDetectionEnabled),
            optDetectionWeight(detections, "emulator",
                defaults.emulatorDetectionWeight),
            application == null
                ? ""
                : application.optString("expected_package_name", ""),
            expectedCertificates(android),
            protectedAssets(protectedAssets),
            apkInventory == null ? 0 : apkInventory.optInt("entry_count", 0),
            apkInventory == null
                ? ""
                : apkInventory.optString("entry_set_sha256", ""),
            apkInventory == null
                ? 0
                : apkInventory.optInt("executable_entry_count", 0),
            apkInventory == null
                ? ""
                : apkInventory.optString("executable_entry_set_sha256", ""),
            true);
        return parsed.isValid() ? parsed : defaults;
      } catch (Throwable ignored) {
        return defaults();
      }
    }

    private boolean isValid() {
      return reportThreshold >= 0
          && reportThreshold < warnThreshold
          && warnThreshold < restrictThreshold
          && restrictThreshold <= terminateThreshold
          && terminateThreshold <= 100
          && startupBudgetMs > 0
          && debuggerDetectionWeight >= 0
          && debuggerDetectionWeight <= 100
          && instrumentationDetectionWeight >= 0
          && instrumentationDetectionWeight <= 100
          && memoryIntegrityWeight >= 0
          && memoryIntegrityWeight <= 100
          && rootDetectionWeight >= 0
          && rootDetectionWeight <= 100
          && emulatorDetectionWeight >= 0
          && emulatorDetectionWeight <= 100
          && scanIntervalMinimumMs <= scanIntervalMaximumMs
          && expectedPackageName.length() > 0
          && !expectedCertificateSha256.isEmpty()
          && !protectedAssets.isEmpty();
    }

    private int nextScanDelayMs() {
      if (scanIntervalMaximumMs <= scanIntervalMinimumMs) {
        return scanIntervalMinimumMs;
      }
      int spread = scanIntervalMaximumMs - scanIntervalMinimumMs;
      return scanIntervalMinimumMs + (int) (Math.random() * (spread + 1L));
    }

    private static int clampInterval(int value) {
      if (value < MIN_MONITOR_INTERVAL_MS) {
        return MIN_MONITOR_INTERVAL_MS;
      }
      if (value > MAX_MONITOR_INTERVAL_MS) {
        return MAX_MONITOR_INTERVAL_MS;
      }
      return value;
    }

    private static int optRiskScore(JSONObject object, String name, int fallback) {
      if (object == null) {
        return fallback;
      }
      int value = object.optInt(name, fallback);
      return value >= 0 && value <= 100 ? value : fallback;
    }

    private static boolean optDetectionEnabled(JSONObject detections, String name,
        boolean fallback) {
      JSONObject detection =
          detections == null ? null : detections.optJSONObject(name);
      return detection == null ? fallback : detection.optBoolean("enabled", fallback);
    }

    private static int optDetectionWeight(JSONObject detections, String name,
        int fallback) {
      JSONObject detection =
          detections == null ? null : detections.optJSONObject(name);
      if (detection == null) {
        return fallback;
      }
      int value = detection.optInt("weight", fallback);
      return value >= 0 && value <= 100 ? value : fallback;
    }

    private boolean packageMatches(Context context) {
      return manifestLoaded
          && context != null
          && expectedPackageName.equals(context.getPackageName());
    }

    private boolean certificateMatches(Context context) {
      if (!manifestLoaded || context == null || expectedCertificateSha256.isEmpty()) {
        return false;
      }

      try {
        List<String> actualDigests = currentCertificateSha256(context);
        for (int i = 0; i < actualDigests.size(); i++) {
          String actual = actualDigests.get(i);
          for (int j = 0; j < expectedCertificateSha256.size(); j++) {
            if (actual.equalsIgnoreCase(expectedCertificateSha256.get(j))) {
              return true;
            }
          }
        }
      } catch (Throwable ignored) {
        return false;
      }

      return false;
    }

    private boolean payloadAssetsMatch(Context context) {
      return verifyAssets(context, false, true) && apkInventoryMatches(context);
    }

    private boolean smallProtectedAssetsMatch(Context context) {
      return verifyAssets(context, true, false);
    }

    private boolean nextRuntimeProtectedAssetMatches(Context context) {
      if (!manifestLoaded || context == null || protectedAssets.isEmpty()) {
        return false;
      }

      String sourceDir = sourceApkPath(context);
      if (sourceDir == null) {
        return false;
      }

      ZipFile apk = null;
      try {
        apk = new ZipFile(sourceDir);
        int assetCount = protectedAssets.size();
        for (int checked = 0; checked < assetCount; checked++) {
          int index = nextRuntimeProtectedAssetIndex % assetCount;
          nextRuntimeProtectedAssetIndex = (index + 1) % assetCount;
          ProtectedAsset asset = protectedAssets.get(index);
          if (!asset.isRuntimeDeferredAsset()) {
            continue;
          }
          return protectedAssetMatches(apk, asset, false);
        }
        return true;
      } catch (Throwable ignored) {
        return false;
      } finally {
        closeQuietly(apk);
      }
    }

    private boolean allRuntimeProtectedAssetsMatch(Context context) {
      if (!manifestLoaded || context == null || protectedAssets.isEmpty()) {
        return false;
      }

      String sourceDir = sourceApkPath(context);
      if (sourceDir == null) {
        return false;
      }

      boolean checkedAny = false;
      ZipFile apk = null;
      try {
        apk = new ZipFile(sourceDir);
        for (int i = 0; i < protectedAssets.size(); i++) {
          ProtectedAsset asset = protectedAssets.get(i);
          if (!asset.isRuntimeDeferredAsset()) {
            continue;
          }
          checkedAny = true;
          if (!protectedAssetMatches(apk, asset, false)) {
            return false;
          }
        }
      } catch (Throwable ignored) {
        return false;
      } finally {
        closeQuietly(apk);
      }

      return true;
    }

    private boolean verifyAssets(Context context, boolean javascriptOnly,
        boolean payloadOnly) {
      if (!manifestLoaded || context == null || protectedAssets.isEmpty()) {
        return false;
      }

      String sourceDir = sourceApkPath(context);
      if (sourceDir == null) {
        return false;
      }

      boolean checkedAny = false;
      ZipFile apk = null;
      try {
        apk = new ZipFile(sourceDir);
        for (int i = 0; i < protectedAssets.size(); i++) {
          ProtectedAsset asset = protectedAssets.get(i);
          boolean isJavascript = asset.isJavascriptBundle();
          if (javascriptOnly != isJavascript) {
            continue;
          }
          if (payloadOnly
              && !("BOOTSTRAP_DEX".equals(asset.kind)
                  || "NATIVE_LIBRARY".equals(asset.kind))) {
            continue;
          }

          checkedAny = true;
          if (!protectedAssetMatches(apk, asset, isJavascript)) {
            return false;
          }
        }
      } catch (Throwable ignored) {
        return false;
      } finally {
        closeQuietly(apk);
      }

      return payloadOnly ? checkedAny : true;
    }

    private boolean apkInventoryMatches(Context context) {
      if (expectedEntryCount == 0
          && expectedEntrySetSha256.length() == 0
          && expectedExecutableEntryCount == 0
          && expectedExecutableEntrySetSha256.length() == 0) {
        return true;
      }
      if (expectedEntrySetSha256.length() != 64
          || expectedExecutableEntrySetSha256.length() != 64) {
        return false;
      }

      String sourceDir = sourceApkPath(context);
      if (sourceDir == null) {
        return false;
      }

      ZipFile apk = null;
      try {
        apk = new ZipFile(sourceDir);
        ApkInventory actual = apkInventory(apk);
        return actual.entryCount == expectedEntryCount
            && actual.executableEntryCount == expectedExecutableEntryCount
            && actual.entrySetSha256.equalsIgnoreCase(expectedEntrySetSha256)
            && actual.executableEntrySetSha256.equalsIgnoreCase(
                expectedExecutableEntrySetSha256);
      } catch (Throwable ignored) {
        return false;
      } finally {
        closeQuietly(apk);
      }
    }

    private static ApkInventory apkInventory(ZipFile apk) throws Exception {
      ArrayList<String> entries = new ArrayList<String>();
      Enumeration<? extends ZipEntry> zipEntries = apk.entries();
      while (zipEntries.hasMoreElements()) {
        ZipEntry entry = zipEntries.nextElement();
        String name = entry.getName();
        if (entry.isDirectory() || isJarSignatureMetadataEntry(name)) {
          continue;
        }
        entries.add(name);
      }
      Collections.sort(entries);

      ArrayList<String> executableEntries = new ArrayList<String>();
      for (int i = 0; i < entries.size(); i++) {
        String entry = entries.get(i);
        if (isExecutableInventoryEntry(entry)) {
          executableEntries.add(entry);
        }
      }

      return new ApkInventory(entries.size(), pathSetSha256(entries),
          executableEntries.size(), pathSetSha256(executableEntries));
    }

    private static String pathSetSha256(List<String> paths) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (int i = 0; i < paths.size(); i++) {
        digest.update(paths.get(i).getBytes("UTF-8"));
        digest.update((byte) 0);
      }
      return hex(digest.digest());
    }

    private static boolean isExecutableInventoryEntry(String path) {
      return isDexEntryPath(path)
          || isNativeLibraryEntry(path)
          || path.endsWith(".dex")
          || path.endsWith(".jar")
          || path.endsWith(".apk")
          || path.endsWith(".so");
    }

    private static boolean isDexEntryPath(String path) {
      if ("classes.dex".equals(path)) {
        return true;
      }
      if (!path.startsWith("classes") || !path.endsWith(".dex")) {
        return false;
      }
      String value = path.substring("classes".length(), path.length() - ".dex".length());
      if (value.length() == 0) {
        return false;
      }
      for (int i = 0; i < value.length(); i++) {
        char ch = value.charAt(i);
        if (ch < '0' || ch > '9') {
          return false;
        }
      }
      return true;
    }

    private static boolean isNativeLibraryEntry(String path) {
      if (!path.startsWith("lib/") || !path.endsWith(".so")) {
        return false;
      }
      int slash = path.indexOf('/', 4);
      return slash > 4 && slash == path.lastIndexOf('/');
    }

    private static boolean isJarSignatureMetadataEntry(String path) {
      String upper = path.toUpperCase(Locale.US);
      return "META-INF/MANIFEST.MF".equals(upper)
          || upper.startsWith("META-INF/")
              && (upper.endsWith(".RSA")
                  || upper.endsWith(".DSA")
                  || upper.endsWith(".EC")
                  || upper.endsWith(".SF"));
    }

    private static String sourceApkPath(Context context) {
      String sourceDir = context.getApplicationInfo() == null
          ? null
          : context.getApplicationInfo().sourceDir;
      return sourceDir == null || sourceDir.length() == 0 ? null : sourceDir;
    }

    private static boolean protectedAssetMatches(ZipFile apk,
        ProtectedAsset asset, boolean enforceStartupJavascriptBudget)
        throws Exception {
      ZipEntry entry = apk.getEntry(asset.path);
      if (entry == null) {
        return false;
      }
      if (enforceStartupJavascriptBudget
          && entry.getSize() > MAX_STARTUP_JAVASCRIPT_HASH_BYTES) {
        return true;
      }

      String actual = zipEntrySha256(apk, entry);
      return actual.equalsIgnoreCase(asset.sha256);
    }

    private static void closeQuietly(ZipFile zipFile) {
      if (zipFile != null) {
        try {
          zipFile.close();
        } catch (Throwable ignored) {
        }
      }
    }

    private static List<String> expectedCertificates(JSONObject android) {
      ArrayList<String> digests = new ArrayList<String>();
      if (android == null) {
        return digests;
      }

      JSONArray values = android.optJSONArray("expected_certificate_sha256");
      if (values == null) {
        return digests;
      }

      for (int i = 0; i < values.length(); i++) {
        String value = values.optString(i, "");
        if (value.length() == 64) {
          digests.add(value.toLowerCase(Locale.US));
        }
      }
      return digests;
    }

    private static List<ProtectedAsset> protectedAssets(JSONArray values) {
      ArrayList<ProtectedAsset> assets = new ArrayList<ProtectedAsset>();
      if (values == null) {
        return assets;
      }

      for (int i = 0; i < values.length(); i++) {
        JSONObject value = values.optJSONObject(i);
        if (value == null) {
          continue;
        }
        String path = value.optString("path", "");
        String sha256 = value.optString("sha256", "");
        String kind = value.optString("kind", "");
        if (path.length() > 0 && sha256.length() == 64 && kind.length() > 0) {
          assets.add(new ProtectedAsset(path, sha256.toLowerCase(Locale.US), kind));
        }
      }

      return assets;
    }
  }

  private static final class ProtectedAsset {
    private final String path;
    private final String sha256;
    private final String kind;

    private ProtectedAsset(String path, String sha256, String kind) {
      this.path = path;
      this.sha256 = sha256;
      this.kind = kind;
    }

    private boolean isJavascriptBundle() {
      return "JAVASCRIPT_BUNDLE".equals(kind);
    }

    private boolean isFlutterAsset() {
      return "FLUTTER_ASSET".equals(kind);
    }

    private boolean isFlutterNativeLibrary() {
      return "FLUTTER_NATIVE_LIBRARY".equals(kind);
    }

    private boolean isRuntimeDeferredAsset() {
      return isJavascriptBundle() || isFlutterAsset() || isFlutterNativeLibrary();
    }
  }

  private static final class ApkInventory {
    private final int entryCount;
    private final String entrySetSha256;
    private final int executableEntryCount;
    private final String executableEntrySetSha256;

    private ApkInventory(int entryCount, String entrySetSha256,
        int executableEntryCount, String executableEntrySetSha256) {
      this.entryCount = entryCount;
      this.entrySetSha256 = entrySetSha256;
      this.executableEntryCount = executableEntryCount;
      this.executableEntrySetSha256 = executableEntrySetSha256;
    }
  }

  @SuppressWarnings("deprecation")
  private static List<String> currentCertificateSha256(Context context) throws Exception {
    PackageManager packageManager = context.getPackageManager();
    String packageName = context.getPackageName();
    ArrayList<String> digests = new ArrayList<String>();
    Signature[] signatures;

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      PackageInfo packageInfo = packageManager.getPackageInfo(
          packageName, PackageManager.GET_SIGNING_CERTIFICATES);
      if (packageInfo.signingInfo == null) {
        return digests;
      }
      signatures = packageInfo.signingInfo.getApkContentsSigners();
    } else {
      PackageInfo packageInfo =
          packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
      signatures = packageInfo.signatures;
    }

    if (signatures == null) {
      return digests;
    }

    for (int i = 0; i < signatures.length; i++) {
      digests.add(sha256Hex(signatures[i].toByteArray()));
    }

    return digests;
  }

  private static String zipEntrySha256(ZipFile zipFile, ZipEntry entry)
      throws Exception {
    InputStream input = zipFile.getInputStream(entry);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] buffer = new byte[8192];
      int bytesRead;
      while ((bytesRead = input.read(buffer)) != -1) {
        digest.update(buffer, 0, bytesRead);
      }
      return hex(digest.digest());
    } finally {
      input.close();
    }
  }

  private static String sha256Hex(byte[] value) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return hex(digest.digest(value));
  }

  private static String hex(byte[] hash) {
    StringBuilder output = new StringBuilder(hash.length * 2);
    for (int i = 0; i < hash.length; i++) {
      int current = hash[i] & 0xff;
      if (current < 16) {
        output.append('0');
      }
      output.append(Integer.toHexString(current));
    }
    return output.toString();
  }

  private static String readAsset(Context context, String assetPath) throws Exception {
    InputStream input = context.getAssets().open(assetPath);
    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int bytesRead;
      while ((bytesRead = input.read(buffer)) != -1) {
        output.write(buffer, 0, bytesRead);
      }
      return output.toString("UTF-8");
    } finally {
      input.close();
    }
  }

  @Override
  public Cursor query(Uri uri, String[] projection, String selection,
      String[] selectionArgs, String sortOrder) {
    return null;
  }

  @Override
  public String getType(Uri uri) {
    return null;
  }

  @Override
  public Uri insert(Uri uri, ContentValues values) {
    return null;
  }

  @Override
  public int delete(Uri uri, String selection, String[] selectionArgs) {
    return 0;
  }

  @Override
  public int update(Uri uri, ContentValues values, String selection,
      String[] selectionArgs) {
    return 0;
  }
}
