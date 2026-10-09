package org.springframework.http;

import java.time.Duration;

public final class ResponseCookie extends HttpCookie {
  private ResponseCookie(String name, String value) {
    super(name, value);
  }

  public Duration getMaxAge() { return null; }

  public String getDomain() { return null; }

  public String getPath() { return null; }

  public boolean isSecure() { return false; }

  public boolean isHttpOnly() { return false; }

  public String getSameSite() { return null; }

  public ResponseCookieBuilder mutate() { return null; }

  @Override
  public String toString() { return null; }

  public static ResponseCookieBuilder from(String name) { return null; }

  public static ResponseCookieBuilder from(String name, String value) { return null; }

  public static ResponseCookieBuilder fromClientResponse(String name, String value) { return null; }

  public interface ResponseCookieBuilder {
    ResponseCookieBuilder value(String value);

    ResponseCookieBuilder maxAge(Duration maxAge);

    ResponseCookieBuilder maxAge(long maxAgeSeconds);

    ResponseCookieBuilder path(String path);

    ResponseCookieBuilder domain(String domain);

    ResponseCookieBuilder secure(boolean secure);

    ResponseCookieBuilder httpOnly(boolean httpOnly);

    ResponseCookieBuilder partitioned(boolean partitioned);

    ResponseCookieBuilder sameSite(String sameSite);

    ResponseCookie build();
  }
}
