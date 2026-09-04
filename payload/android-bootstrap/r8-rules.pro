-keep class com.rasp.runtime.bootstrap.RaspInitProvider {
    public <init>();
    public boolean onCreate();
}
-keep class com.rasp.runtime.bootstrap.RaspRuntimeEntry {
    public static boolean onProviderCreate(android.content.Context, java.lang.String);
    private static native int nativeInitialize(...);
    private static native int nativeMonitorScan(...);
    private static native int nativeLastActionCode();
    private static native java.lang.String nativeLastReportJson();
}
-allowaccessmodification
