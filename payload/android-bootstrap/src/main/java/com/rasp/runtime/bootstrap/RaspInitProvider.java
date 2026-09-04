package com.rasp.runtime.bootstrap;

import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import org.json.JSONObject;

public final class RaspInitProvider extends ContentProvider {
  static volatile byte[] K =
      b(0x4b, 0x3f, 0x5a, 0xc8, 0x21);
  private static final byte[] B0 =
      b(0x84, 0xea, 0xcf, 0x31, 0x59, 0xb7, 0xf9, 0x50, 0x12, 0xc7);
  private static final byte[] B1 = b(
      0x0d, 0x41, 0x96, 0xee, 0x7e, 0x47, 0x91, 0xab, 0x62, 0x34, 0xe9,
      0xd9, 0x52, 0x02, 0xd5, 0x7f, 0x48, 0x82, 0xdc, 0x3a, 0x7a, 0xe9,
      0xe4, 0x53, 0x19, 0xc1, 0xbb, 0x43, 0x18, 0xc8, 0xdf, 0xa1, 0xed,
      0x2e, 0x6a);
  static final byte[] B2 = b(
      0x24, 0x6e, 0xb8, 0xc0, 0x03, 0x7d, 0xbf, 0xf1, 0x31, 0x6f, 0xcd,
      0xa4, 0x6c, 0x3f, 0xe3, 0x5a, 0x61, 0xae, 0xec, 0x7e);
  private static final byte[] B3 = b(
      0xfa, 0x3c, 0x65, 0x9b, 0xc3, 0x12, 0x42, 0xf6, 0xb5, 0x59, 0x1a,
      0xfc, 0xa6, 0x76, 0x3d, 0x03, 0x4b, 0x99, 0xd4, 0x3a, 0x1c, 0x4e,
      0x88, 0xba, 0x6e, 0x31, 0xe7, 0x9e, 0x51, 0x16, 0xd4, 0x37);
  private static final byte[] B4 =
      b(0x3c, 0x6a, 0xa7, 0xd3, 0x06);
  private static final byte[] B5 =
      b(0x40, 0x72, 0xa8, 0xc2, 0x14, 0x4f);
  private static final byte[] B6 =
      b(0x1b, 0x50, 0x88, 0xe1);
  private static final byte[] B7 =
      b(0xb8, 0xe6, 0x21, 0x6c, 0xb7, 0xee, 0x22, 0x0a, 0xce, 0x95, 0x5f,
          0x2f);
  private static final byte[] B8 =
      b(0x75, 0xbf, 0xfd, 0x1d, 0x5c, 0x80, 0xc2, 0x50, 0x0c);
  private static final byte[] B9 =
      b(0xd7, 0x03, 0x76, 0xa9, 0xc3, 0x07, 0x53, 0xeb, 0xa5, 0x77, 0x0d,
          0xc1, 0x91, 0x48, 0x16, 0xc2);
  private static final byte[] B10 = b(
      0x2c, 0x7f, 0xbb, 0xda, 0x06, 0x5c, 0x9d, 0xf2, 0x62, 0x26, 0x1c,
      0xf0, 0xaa, 0x75, 0x3d, 0x0b, 0x5d, 0x8c, 0xc0);
  private static final byte[] B11 =
      b(0x3c, 0x6c, 0xa4, 0xca, 0xf4, 0x26, 0x6f, 0xc9, 0x85, 0x1a, 0x1d,
          0xe5, 0xbb, 0x7a, 0x2a, 0x29, 0x6c, 0xf2, 0xf3, 0x01, 0x5a, 0x83,
          0xd8, 0x68, 0x71, 0xe7, 0xd6, 0xb3, 0x68, 0x3f, 0xe7, 0x56, 0x90);
  private static final byte[] B12 =
      b(0x10, 0x50, 0x91, 0xf7, 0x3e, 0x5d, 0x83, 0xa7, 0x63, 0x78, 0xe9,
          0x93, 0x43, 0x4c, 0xc5, 0x73, 0x5d, 0x95, 0xd6, 0x3a, 0x6c, 0xb6,
          0xf0, 0x12, 0x02, 0xc6, 0xbc, 0x50, 0x0a, 0xd5, 0x9d, 0xaa, 0xfc,
          0x2d, 0x61);
  private static final byte[] B13 =
      b(0xdf, 0x09, 0x59, 0xfa, 0xcc, 0x11, 0x56, 0xe6, 0xa6, 0x24, 0x2d,
          0xdb, 0x85, 0x4d, 0x7e, 0xd2, 0x04, 0x4e, 0x88, 0xaa, 0x2a, 0x6e,
          0xa4, 0x88, 0x52, 0x3d, 0xf5, 0x83, 0x45, 0x14, 0xc8);
  private static final byte[] B14 =
      b(0x37, 0x6d, 0xb2, 0xd8, 0x1e, 0x3e, 0x7c, 0x8d, 0x87, 0x48, 0x1f,
          0xf4, 0xae, 0x2f, 0x30, 0x24, 0x7a, 0xbb);
  private static final byte[] B15 =
      b(0x94, 0xda, 0x1f, 0x61, 0xda, 0xfc, 0x08, 0x4c, 0x0b, 0xdf, 0x90,
          0x29, 0x2e, 0xe8, 0xab, 0x96, 0xd3, 0x0f, 0x3c, 0x92, 0xde, 0x1e,
          0x42, 0xe1, 0xab, 0x73);
  private static final byte[] B16 = b(
      0xe3, 0x31, 0x64, 0x90, 0xd9, 0x11, 0x4d, 0xed, 0xab, 0xd7, 0x55,
      0x2c, 0xe8, 0xb2, 0x6a, 0xd4, 0x09, 0x5b, 0xc0, 0xd0, 0x00, 0x52,
      0x82, 0xa8, 0x6b, 0x2b, 0xe9, 0x9f, 0x5a, 0x0e);
  private static final byte[] B17 =
      b(0x2b, 0x7d, 0xb7, 0xdb, 0x1b, 0x57, 0x9c, 0xb8, 0x72, 0x6b, 0x0e,
          0xf4, 0xa4, 0x6b, 0x39, 0x18, 0x5b, 0xc3, 0xc9, 0x3c, 0x66, 0x96,
          0xdc, 0x6c, 0x32, 0xfa, 0xec, 0x58, 0x14, 0xd9, 0x81, 0x48, 0x86,
          0xd6);
  private static final byte[] B18 = b(0xdc, 0x00);
  private static final byte[] B19 = b(0xd6);
  private static final byte[] B20 = b(0x62, 0x75, 0xbf, 0xd7);
  private static final byte[] B21 =
      b(0x50, 0x8c, 0xc8, 0x5f, 0x05, 0xdd, 0xeb);
  private static final byte[] B22 =
      b(0x28, 0x72, 0xad, 0xb1, 0x69);
  private static final byte[] B23 = b(
      0xda, 0x06, 0x56, 0xba, 0xe9, 0x33, 0x7b, 0xe3, 0x93, 0x5f, 0x3b,
      0xc7, 0x80, 0x4a, 0x2c, 0x39, 0x6a);
  private static final byte[] B24 = b(
      0xdb, 0x09, 0x57, 0xb9, 0xe8, 0x34, 0x7a, 0xe0, 0x80, 0x74, 0x27,
      0xcf, 0x8b, 0x58, 0x16, 0x08, 0x6c, 0xac, 0xeb, 0x0b, 0x29, 0x63,
      0xb3, 0x81, 0x47, 0x3a, 0xcf, 0xb0, 0x60, 0x20, 0xed, 0x68);
  private static final byte[] B25 =
      b(0x62, 0x58, 0x94, 0xe4, 0x25, 0x62);
  private static final byte[] B26 =
      b(0x71, 0xb1, 0xe7, 0x06, 0x5e, 0x85, 0xb8);
  static final byte[] B27 =
      b(0x73, 0xa5, 0xf0, 0x1e, 0x58, 0x89, 0xb9);
  static final byte[] B28 = b(
      0xcc, 0x1c, 0x54, 0xba, 0xe4, 0x36, 0x7f, 0xd9, 0x95, 0x75, 0x2d,
      0xd5, 0x8b, 0x4a, 0x1a, 0x39, 0x7c);
  private static final byte[] B29 =
      b(0x52, 0xa0, 0xf7, 0x0f, 0x40, 0xa6, 0xdb, 0x73);
  static final byte[] B30 =
      b(0xb7, 0xf8, 0xcf, 0x24, 0x7e, 0x80, 0xe0, 0x54, 0x0a, 0xcb);
  static final byte[] B31 =
      b(0xb5, 0xe7, 0xdd, 0x32, 0x79, 0x80, 0xfe, 0x54, 0x13, 0xc6);
  static final byte[] B32 =
      b(0x61, 0x5f, 0x99, 0xbf, 0x73, 0x2d);
  static final byte[] B33 =
      b(0xb3, 0xe5, 0xdf, 0x33, 0x73, 0xaf, 0xe4, 0x5c, 0x11, 0xcd);
  private static final byte[] B34 = b(
      0x0f, 0x55, 0x8b, 0xed, 0x24, 0x40, 0x8e, 0x9c, 0x60, 0x2c, 0xe0,
      0x96, 0x4c, 0x04, 0xc9, 0x75, 0x73, 0x9c, 0xc9, 0x72);
  private static final byte[] B35 = b(
      0x6f, 0x63, 0xa1, 0xcf, 0x11, 0x50, 0x9c, 0xa2, 0x48, 0x2a, 0x08,
      0xe2, 0xac, 0x79, 0x25, 0x35, 0x52, 0x93, 0x98);
  private static final byte[] B36 = b(
      0xf1, 0xf9, 0xcb, 0x21, 0x77, 0xaa, 0xe6, 0x44, 0x26, 0xc0, 0x92,
      0x7c, 0x0a, 0xd3, 0x8f, 0x93, 0xe4, 0x22, 0x6c, 0x95, 0xd0, 0x0a,
      0x46, 0x00, 0x94);
  private static final byte[] B37 = b(
      0xc5, 0xd7, 0x1d, 0x7d, 0xad, 0xeb, 0x26, 0x14, 0xe4, 0xac, 0x7e,
      0x08, 0x9c);
  private static final byte[] B38 =
      b(0x10, 0xb4, 0xfd, 0x17, 0x4d, 0x96, 0xdc, 0x2a);
  private static final String S0 = s(B0);
  private static final String S1 =
      s(B1);
  private static final String S2 =
      s(B4);
  private static final String S3 =
      s(B5);
  private static final String S4 =
      s(B6);
  private static final String S5 =
      s(B7);
  private static final String S6 =
      s(B8);
  private static final String S7 =
      s(B10);
  private static final String S8 =
      s(B11);
  private static final String S9 =
      s(B12);
  private static final String S10 =
      s(B13);
  private static final String S11 =
      s(B14);
  private static final String S12 =
      s(B15);
  static final String S13 =
      s(B16);
  static final String S14 =
      s(B17);
  private static final String S15 = s(B18);
  private static final String S16 = s(B19);
  private static final String S17 = s(B20);
  private static final String S18 = s(B21);
  private static final String S19 = s(B22);
  static final String S20 = s(B29);
  private static final String S21 =
      s(B34);
  private static final String S22 =
      s(B35);
  private static final String S23 =
      s(B36);
  private static final String S24 = s(B37);
  private static final String S25 = s(B38);
  private static final int C0 = 0;
  private static final int C1 = 1;
  private static final int C2 = 2;
  private static final int C3 = 3;
  private static final int C4 = 4;

  private static byte[] b(int... values) {
    byte[] output = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      output[i] = (byte) values[i];
    }
    return output;
  }

  private static String s(byte[] encoded) {
    return s(encoded, k0());
  }

  static String s(byte[] encoded, int key) {
    char[] decoded = new char[encoded.length];
    int normalizedKey = key & 0xff;
    for (int i = 0; i < encoded.length; i++) {
      decoded[i] = (char) (((int) encoded[i] & 0xff)
          ^ m(normalizedKey, i, encoded.length));
    }
    return new String(decoded);
  }

  private static int k0() {
    return K[2] & 0xff;
  }

  static int k1(String buildId) {
    int sourceKey = k0();
    if (!vh(buildId)) {
      return sourceKey;
    }
    int key = ((x(buildId.charAt(4)) << 4)
        | x(buildId.charAt(5))) ^ 0x9e;
    int[] tweaks = new int[] {0x73, 0xb5, 0x2d, 0xe1};
    for (int i = 0; i < tweaks.length; i++) {
      if (key != 0 && key != sourceKey) {
        return key & 0xff;
      }
      key ^= tweaks[i];
    }
    return key == 0 || key == sourceKey ? ((sourceKey ^ 0xa5) & 0xff) : key & 0xff;
  }

  private static int k2(String manifestBody) {
    if (manifestBody == null || manifestBody.length() == 0) {
      return k0();
    }
    try {
      JSONObject root = new JSONObject(manifestBody);
      return k1(root.optString(S20, ""));
    } catch (Throwable ignored) {
      return k0();
    }
  }

  private static int x(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return 0;
  }

  private static int m(int key, int index, int length) {
    int position = (index + 1) & 0xff;
    int span = length & 0xff;
    int mix = (0x9d + ((position * 0x3d) & 0xff) + ((span * 0x11) & 0xff))
        & 0xff;
    int rotated = ((position << 3) | (position >>> 5)) & 0xff;
    return key ^ mix ^ rotated;
  }

  @Override
  public boolean onCreate() {
    long startupStartNs = SystemClock.elapsedRealtimeNanos();
    String manifestBody = null;
    try {
      Context context = getContext();
      Context applicationContext =
          context == null ? null : context.getApplicationContext();
      manifestBody = r(applicationContext);
      D descriptor = D.g(manifestBody);
      byte[] encryptedRuntime = ab(applicationContext, descriptor.c);
      if (!sx(encryptedRuntime).equalsIgnoreCase(descriptor.e)) {
        throw new IllegalStateException(S8);
      }
      byte[] runtimeDex = c(encryptedRuntime, descriptor);
      ClassLoader classLoader = l(applicationContext, runtimeDex);
      Class<?> entryClass = classLoader.loadClass(descriptor.d);
      Method entrypoint =
          entryClass.getMethod(s(B9,
                  descriptor.b),
              Context.class, String.class);
      entrypoint.invoke(null, applicationContext, manifestBody);
      return true;
    } catch (InvocationTargetException error) {
      Throwable cause = error.getCause();
      if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      }
      if (cause instanceof Error) {
        throw (Error) cause;
      }
      return f(startupStartNs, manifestBody);
    } catch (Throwable error) {
      return f(startupStartNs, manifestBody);
    }
  }

  private static boolean f(long startupStartNs, String manifestBody) {
    int action = pa(manifestBody);
    tm(startupStartNs, bm(manifestBody), false, action);
    ap(action);
    return true;
  }

  private static ClassLoader l(Context context, byte[] dexBytes)
      throws Exception {
    if (context == null) {
      throw new IllegalStateException(S7);
    }
    ClassLoader parent = RaspInitProvider.class.getClassLoader();
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      return new InMemoryDexClassLoader(ByteBuffer.wrap(dexBytes), parent);
    }

    File root = new File(context.getCodeCacheDir(), S15);
    File optimized = new File(root, S16);
    if (!optimized.mkdirs() && !optimized.isDirectory()) {
      throw new IllegalStateException(S9);
    }
    File dexFile = new File(root, sx(dexBytes) + S17);
    w(dexFile, dexBytes);
    return new DexClassLoader(
        dexFile.getAbsolutePath(), optimized.getAbsolutePath(), null, parent);
  }

  private static void w(File file, byte[] bytes) throws Exception {
    if (file.isFile() && file.length() == bytes.length) {
      return;
    }
    File parent = file.getParentFile();
    if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
      throw new IllegalStateException(S10);
    }
    FileOutputStream output = new FileOutputStream(file);
    try {
      output.write(bytes);
    } finally {
      output.close();
    }
  }

  private static byte[] c(byte[] input, D descriptor)
      throws Exception {
    byte[] seed = sd(descriptor);
    byte[] output = new byte[input.length];
    int offset = 0;
    int counter = 0;
    while (offset < input.length) {
      byte[] block = kb(seed, counter);
      for (int i = 0; i < block.length && offset < input.length; i++) {
        output[offset] = (byte) (input[offset] ^ block[i]);
        offset++;
      }
      counter++;
    }
    return output;
  }

  private static byte[] sd(D descriptor) throws Exception {
    MessageDigest digest = MessageDigest.getInstance(S18);
    digest.update(s(B3, descriptor.b)
        .getBytes(S19));
    digest.update((byte) 0);
    digest.update(descriptor.a.getBytes(S19));
    digest.update((byte) 0);
    digest.update(descriptor.c.getBytes(S19));
    digest.update((byte) 0);
    digest.update(descriptor.d.getBytes(S19));
    return digest.digest();
  }

  private static byte[] kb(byte[] seed, int counter) throws Exception {
    MessageDigest digest = MessageDigest.getInstance(S18);
    digest.update(seed);
    digest.update((byte) ((counter >>> 24) & 0xff));
    digest.update((byte) ((counter >>> 16) & 0xff));
    digest.update((byte) ((counter >>> 8) & 0xff));
    digest.update((byte) (counter & 0xff));
    return digest.digest();
  }

  private static String r(Context context) {
    ArrayList<String> candidates = ca(context);
    for (int i = 0; i < candidates.size(); i++) {
      String candidate = candidates.get(i);
      try {
        return ra(context, candidate);
      } catch (Throwable ignored) {
      }
    }
    return null;
  }

  private static ArrayList<String> ca(Context context) {
    ArrayList<String> candidates = new ArrayList<String>();
    acm(candidates, pm(context));
    acm(candidates, S1);
    return candidates;
  }

  private static String pm(Context context) {
    if (context == null) {
      return null;
    }
    try {
      PackageManager packageManager = context.getPackageManager();
      ProviderInfo providerInfo = packageManager.getProviderInfo(
          new ComponentName(context, RaspInitProvider.class),
          PackageManager.GET_META_DATA);
      Bundle metadata = providerInfo == null ? null : providerInfo.metaData;
      if (metadata == null || metadata.isEmpty()) {
        return null;
      }
      ArrayList<String> keys = new ArrayList<String>(metadata.keySet());
      Collections.sort(keys);
      for (int i = 0; i < keys.size(); i++) {
        Object value = metadata.get(keys.get(i));
        if (value instanceof String) {
          String assetPath = (String) value;
          if (vp(assetPath)) {
            return assetPath;
          }
        }
      }
    } catch (Throwable ignored) {
    }
    return null;
  }

  private static void acm(ArrayList<String> candidates,
      String assetPath) {
    if (!vp(assetPath) || candidates.contains(assetPath)) {
      return;
    }
    candidates.add(assetPath);
  }

  private static String ra(Context context, String assetPath)
      throws Exception {
    return new String(ab(context, assetPath), S19);
  }

  private static byte[] ab(Context context, String assetPath)
      throws Exception {
    if (context == null || !vp(assetPath)) {
      throw new IllegalStateException(S11);
    }
    InputStream input = context.getAssets().open(assetPath);
    try {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int bytesRead;
      while ((bytesRead = input.read(buffer)) != -1) {
        output.write(buffer, 0, bytesRead);
      }
      return output.toByteArray();
    } finally {
      input.close();
    }
  }

  private static int bm(String manifestBody) {
    try {
      int key = k2(manifestBody);
      JSONObject runtime = rp(manifestBody);
      int value = runtime == null
          ? 50
          : runtime.optInt(s(B23, key), 50);
      return value > 0 ? value : 50;
    } catch (Throwable ignored) {
      return 50;
    }
  }

  private static int pa(String manifestBody) {
    try {
      int key = k2(manifestBody);
      JSONObject runtime = rp(manifestBody);
      String action = runtime == null
          ? S6
          : runtime.optString(
              s(B24, key),
              S6);
      return ai(action);
    } catch (Throwable ignored) {
      return C4;
    }
  }

  private static JSONObject rp(String manifestBody) throws Exception {
    if (manifestBody == null || manifestBody.length() == 0) {
      return null;
    }
    int key = k2(manifestBody);
    JSONObject root = new JSONObject(manifestBody);
    JSONObject policy = root.optJSONObject(s(B25, key));
    return policy == null
        ? null
        : policy.optJSONObject(s(B26, key));
  }

  private static void tm(long startupStartNs, int budgetMs,
      boolean initialized, int action) {
    long elapsedNs = SystemClock.elapsedRealtimeNanos() - startupStartNs;
    long durationMs = Math.max(0L, elapsedNs / 1000000L);
    if (elapsedNs > 0L && elapsedNs % 1000000L != 0L) {
      durationMs++;
    }
    boolean budgetExceeded = durationMs > budgetMs;
    String message = S21 + durationMs
        + S22 + budgetMs
        + S23 + budgetExceeded
        + S24 + initialized
        + S25 + an(action);
    if (budgetExceeded) {
      Log.w(S0, message);
    } else {
      Log.i(S0, message);
    }
  }

  private static void ap(int action) {
    if (action == C3) {
      throw new IllegalStateException(S12);
    }
    if (action == C4) {
      android.os.Process.killProcess(android.os.Process.myPid());
      System.exit(10);
    }
  }

  private static int ai(String action) {
    if (S3.equals(action)) {
      return C1;
    }
    if (S4.equals(action)) {
      return C2;
    }
    if (S5.equals(action)) {
      return C3;
    }
    if (S6.equals(action)) {
      return C4;
    }
    return C0;
  }

  private static String an(int action) {
    switch (action) {
      case C1:
        return S3;
      case C2:
        return S4;
      case C3:
        return S5;
      case C4:
        return S6;
      case C0:
      default:
        return S2;
    }
  }

  private static String sx(byte[] value) throws Exception {
    MessageDigest digest = MessageDigest.getInstance(S18);
    return h(digest.digest(value));
  }

  private static String h(byte[] hash) {
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

  static boolean vp(String assetPath) {
    if (assetPath == null || assetPath.length() == 0
        || assetPath.length() > 240 || assetPath.startsWith("/")
        || assetPath.startsWith("\\") || assetPath.indexOf('\\') >= 0) {
      return false;
    }
    String[] segments = assetPath.split("/");
    for (int i = 0; i < segments.length; i++) {
      String segment = segments[i];
      if (segment.length() == 0 || ".".equals(segment) || "..".equals(segment)) {
        return false;
      }
    }
    return true;
  }

  static boolean vc(String value) {
    if (value == null || value.length() == 0) {
      return false;
    }
    String[] segments = value.split("\\.");
    if (segments.length < 2) {
      return false;
    }
    for (int i = 0; i < segments.length; i++) {
      if (!vi(segments[i])) {
        return false;
      }
    }
    return true;
  }

  private static boolean vi(String value) {
    if (value == null || value.length() == 0) {
      return false;
    }
    char first = value.charAt(0);
    if (!(first == '_' || first >= 'A' && first <= 'Z'
        || first >= 'a' && first <= 'z')) {
      return false;
    }
    for (int i = 1; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (!(ch == '_' || ch >= 'A' && ch <= 'Z'
          || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9')) {
        return false;
      }
    }
    return true;
  }

  static boolean vh(String value) {
    if (value == null || value.length() != 64) {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
          || (ch >= 'A' && ch <= 'F'))) {
        return false;
      }
    }
    return true;
  }

  static final class D {
    final String a;
    final int b;
    final String c;
    final String d;
    final String e;

    D(String buildId, int stringXorKey, String assetPath,
        String className, String sha256) {
      this.a = buildId;
      this.b = stringXorKey;
      this.c = assetPath;
      this.d = className;
      this.e = sha256;
    }

    static D g(String manifestBody)
        throws Exception {
      if (manifestBody == null || manifestBody.length() == 0) {
        throw new IllegalStateException(S13);
      }
      JSONObject root = new JSONObject(manifestBody);
      String buildId = root.optString(S20, "");
      int key = k1(buildId);
      JSONObject payload = root.optJSONObject(s(B27, key));
      JSONObject runtime = payload == null
          ? null
          : payload.optJSONObject(s(B28, key));
      String assetPath = runtime == null
          ? ""
          : runtime.optString(s(B30, key), "");
      String className = runtime == null
          ? ""
          : runtime.optString(s(B31, key), "");
      String sha256 = runtime == null
          ? ""
          : runtime.optString(s(B32, key), "");
      String encryption = runtime == null
          ? ""
          : runtime.optString(s(B33, key), "");
      if (!vh(buildId) || !vp(assetPath)
          || !vc(className) || !vh(sha256)
          || !s(B2, key).equals(encryption)) {
        throw new IllegalStateException(S14);
      }
      return new D(
          buildId.toLowerCase(), key, assetPath, className, sha256.toLowerCase());
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
