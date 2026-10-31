package org.springframework.http;

import java.util.List;

public class HttpHeaders {
  public static final String SET_COOKIE = "Set-Cookie";

  public static final String CONTENT_TYPE = "Content-Type";

  public HttpHeaders() {}

  public void add(String headerName, String headerValue) {}

  public void set(String headerName, String headerValue) {}

  public List<String> put(String headerName, List<String> headerValues) { return null; }
}
