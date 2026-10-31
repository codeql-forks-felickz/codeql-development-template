package org.springframework.http;

public class ResponseEntity<T> {
  public static <T> ResponseEntity<T> ok(T body) {
    return null;
  }

  public static BodyBuilder ok() {
    return null;
  }

  public interface HeadersBuilder<B extends HeadersBuilder<B>> {
    B header(String headerName, String... headerValues);

    B headers(HttpHeaders headers);
  }

  public interface BodyBuilder extends HeadersBuilder<BodyBuilder> {
    <T> ResponseEntity<T> body(T body);
  }
}
