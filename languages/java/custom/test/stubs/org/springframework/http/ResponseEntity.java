package org.springframework.http;

public class ResponseEntity<T> {
  public ResponseEntity(T body, HttpHeaders headers, int status) {}

  public static BodyBuilder ok() { return null; }

  public static BodyBuilder status(int status) { return null; }

  public interface HeadersBuilder<B extends HeadersBuilder<B>> {
    B header(String headerName, String... headerValues);

    B headers(HttpHeaders headers);

    <T> ResponseEntity<T> build();
  }

  public interface BodyBuilder extends HeadersBuilder<BodyBuilder> {
    <T> ResponseEntity<T> body(T body);
  }
}
