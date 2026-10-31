package org.apache.hc.core5.http.io.support;

import org.apache.hc.core5.http.support.AbstractMessageBuilder;

public class ClassicRequestBuilder extends AbstractMessageBuilder<Object> {
  public static ClassicRequestBuilder get(String uri) {
    return null;
  }

  @Override
  public ClassicRequestBuilder addHeader(String name, String value) {
    return this;
  }
}
