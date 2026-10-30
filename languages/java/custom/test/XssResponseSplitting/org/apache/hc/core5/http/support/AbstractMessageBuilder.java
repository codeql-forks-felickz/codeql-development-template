package org.apache.hc.core5.http.support;

import org.apache.hc.core5.http.Header;

public abstract class AbstractMessageBuilder<T> {
  public AbstractMessageBuilder<T> addHeader(Header header) {
    return this;
  }

  public AbstractMessageBuilder<T> addHeader(String name, String value) {
    return this;
  }

  public AbstractMessageBuilder<T> setHeader(Header header) {
    return this;
  }

  public AbstractMessageBuilder<T> setHeader(String name, String value) {
    return this;
  }
}
