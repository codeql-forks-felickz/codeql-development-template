package org.apache.logging.log4j;

import java.util.Map;

public final class ThreadContext {
  public static void put(String key, String value) {}

  public static void putIfNull(String key, String value) {}

  public static void putAll(Map<String, String> m) {}

  public static void push(String message) {}

  public static void push(String message, Object... args) {}

  public static String get(String key) {
    return null;
  }
}
