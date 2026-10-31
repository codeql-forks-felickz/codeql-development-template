package org.apache.logging.log4j;

import java.util.List;
import java.util.Map;

public class CloseableThreadContext {
  public static CloseableThreadContext.Instance put(String key, String value) {
    return null;
  }

  public static CloseableThreadContext.Instance putAll(Map<String, String> values) {
    return null;
  }

  public static CloseableThreadContext.Instance push(String message) {
    return null;
  }

  public static CloseableThreadContext.Instance push(String message, Object... args) {
    return null;
  }

  public static CloseableThreadContext.Instance pushAll(List<String> messages) {
    return null;
  }

  public static class Instance implements AutoCloseable {
    public Instance put(String key, String value) {
      return this;
    }

    public Instance push(String message) {
      return this;
    }

    @Override
    public void close() {}
  }
}
