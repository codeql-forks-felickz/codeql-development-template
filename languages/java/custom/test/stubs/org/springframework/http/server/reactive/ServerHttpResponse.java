package org.springframework.http.server.reactive;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

public interface ServerHttpResponse {
  HttpHeaders getHeaders();

  void addCookie(ResponseCookie cookie);
}
