package org.apache.hc.client5.http.classic.methods;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpRequest;

public class HttpGet implements HttpRequest {
  public HttpGet(String uri) {}

  public void addHeader(Header header) {}

  public void addHeader(String name, Object value) {}

  public void setHeader(Header header) {}

  public void setHeader(String name, Object value) {}
}
