package org.apache.hc.core5.http;

public interface HttpMessage {
  void addHeader(Header header);

  void addHeader(String name, Object value);

  void setHeader(Header header);

  void setHeader(String name, Object value);
}
