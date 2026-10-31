package org.springframework.http;

import java.net.URI;
import org.springframework.util.MultiValueMap;

public class ResponseEntity<T> {
  public ResponseEntity(HttpStatus status) {}

  public ResponseEntity(MultiValueMap<String, String> headers, HttpStatus status) {}

  public static BodyBuilder status(HttpStatus status) { return null; }

  public interface HeadersBuilder<B extends HeadersBuilder<B>> {
    B header(String headerName, String... headerValues);

    B location(URI location);

    <T> ResponseEntity<T> build();
  }

  public interface BodyBuilder extends HeadersBuilder<BodyBuilder> {}
}
