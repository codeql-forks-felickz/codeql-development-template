package org.apache.http.client.methods;

import org.apache.http.Header;

public class RequestBuilder {
  public static RequestBuilder get(String uri) {
    return null;
  }

  public RequestBuilder addHeader(Header header) {
    return this;
  }

  public RequestBuilder addHeader(String name, String value) {
    return this;
  }

  public RequestBuilder setHeader(Header header) {
    return this;
  }

  public RequestBuilder setHeader(String name, String value) {
    return this;
  }
}
