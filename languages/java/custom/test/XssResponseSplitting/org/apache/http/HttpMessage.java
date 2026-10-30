package org.apache.http;

public interface HttpMessage {
  void addHeader(Header header);

  void addHeader(String name, String value);

  void setHeader(Header header);

  void setHeader(String name, String value);
}
