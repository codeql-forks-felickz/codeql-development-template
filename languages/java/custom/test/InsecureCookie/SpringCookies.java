import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;

public class SpringCookies {
  private static final String COOKIE_PATH = "/app";

  public ResponseEntity<String> badPathOnly(String sessionId, String content) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).path(COOKIE_PATH).build();
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString()) // BAD
        .body(content);
  }

  public ResponseEntity<String> badHttpOnlyOnly(String sessionId, String content) {
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildHttpOnlySessionCookie("SESSION", sessionId).toString()) // BAD
        .body(content);
  }

  public ResponseEntity<String> badSecureFalse(String sessionId, String content) {
    ResponseCookie cookie =
        ResponseCookie.from("SESSION", sessionId).path(COOKIE_PATH).secure(false).build();
    return ResponseEntity.ok().header("Set-Cookie", cookie.toString()).body(content); // BAD
  }

  public ResponseEntity<String> badHttpHeaders(String sessionId, String content) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).build();
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.SET_COOKIE, cookie.toString()); // BAD
    return ResponseEntity.ok().headers(headers).body(content);
  }

  public ResponseEntity<String> badHttpHeadersSet(String sessionId, String content) {
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.SET_COOKIE, "" + ResponseCookie.from("SESSION", sessionId).build()); // BAD
    return ResponseEntity.ok().headers(headers).body(content);
  }

  public void badReactive(ServerHttpResponse response, String sessionId) {
    response.addCookie(ResponseCookie.from("SESSION", sessionId).httpOnly(true).build()); // BAD
  }

  public ResponseEntity<String> goodSecure(String sessionId, String content) {
    ResponseCookie ok =
        ResponseCookie.from("SESSION", sessionId)
            .path(COOKIE_PATH)
            .secure(true)
            .httpOnly(true)
            .sameSite("Strict")
            .build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, ok.toString()).body(content); // GOOD
  }

  public ResponseEntity<String> goodSecureVariable(String sessionId, String content) {
    ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("SESSION", sessionId);
    builder.path(COOKIE_PATH);
    builder.secure(true);
    ResponseCookie cookie = builder.build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD
  }

  public ResponseEntity<String> goodSecureHelper(String sessionId, String content) {
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildSecureSessionCookie("SESSION", sessionId).toString()) // GOOD
        .body(content);
  }

  public ResponseEntity<String> goodSecureConfigured(
      String sessionId, String content, boolean secureCookies) {
    ResponseCookie cookie =
        ResponseCookie.from("SESSION", sessionId).secure(secureCookies).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: not known to be false
  }

  public ResponseEntity<String> goodRemoval(String content) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", "").path(COOKIE_PATH).maxAge(0).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: deletes the cookie
  }

  public ResponseEntity<String> goodRemovalDuration(String content) {
    ResponseCookie cookie =
        ResponseCookie.from("SESSION", "").maxAge(Duration.ZERO).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: deletes the cookie
  }

  public ResponseEntity<String> goodMutate(ResponseCookie existing, String content) {
    ResponseCookie cookie = existing.mutate().path(COOKIE_PATH).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: attributes unknown
  }

  public ResponseEntity<String> goodOtherHeader(String sessionId, String content) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).build();
    return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, cookie.toString()).body(content); // GOOD: not a Set-Cookie header
  }

  public void goodReactive(ServerHttpResponse response, String sessionId) {
    response.addCookie(ResponseCookie.from("SESSION", sessionId).secure(true).build()); // GOOD
  }

  private static ResponseCookie buildHttpOnlySessionCookie(String cookieName, String sessionId) {
    return ResponseCookie.from(cookieName, sessionId).path(COOKIE_PATH).httpOnly(true).build();
  }

  private static ResponseCookie buildSecureSessionCookie(String cookieName, String sessionId) {
    return ResponseCookie.from(cookieName, sessionId).path(COOKIE_PATH).secure(true).build();
  }
}
