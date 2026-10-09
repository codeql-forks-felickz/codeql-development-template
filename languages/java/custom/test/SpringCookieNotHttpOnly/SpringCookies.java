import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;

public class SpringCookies {
  public static final String LEVEL1_COOKIE = "APP_SESSION_LEVEL1";
  private static final String COOKIE_PATH = "/app";

  public ResponseEntity<String> badPathOnly(String sessionId, String content) {
    ResponseCookie cookie = ResponseCookie.from(LEVEL1_COOKIE, sessionId).path(COOKIE_PATH).build();
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString()) // BAD
        .body(content);
  }

  public ResponseEntity<String> badSecureOnly(String token, String content) {
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildSecureCookie("auth-token", token).toString()) // BAD
        .body(content);
  }

  public ResponseEntity<String> badHttpOnlyFalse(String sessionId, String content) {
    ResponseCookie cookie =
        ResponseCookie.from("SESSIONID", sessionId).secure(true).httpOnly(false).build();
    return ResponseEntity.ok().header("Set-Cookie", cookie.toString()).body(content); // BAD
  }

  public void badReactive(ServerHttpResponse response, String sessionId) {
    response.addCookie(ResponseCookie.from("SESSION", sessionId).secure(true).build()); // BAD
  }

  public ResponseEntity<String> goodHttpOnly(String sessionId, String content) {
    ResponseCookie cookie =
        ResponseCookie.from(LEVEL1_COOKIE, sessionId).path(COOKIE_PATH).httpOnly(true).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD
  }

  public ResponseEntity<String> goodHttpOnlyHelper(String sessionId, String content) {
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, buildHttpOnlyCookie("SESSION", sessionId).toString()) // GOOD
        .body(content);
  }

  public ResponseEntity<String> goodHttpOnlyConfigured(
      String sessionId, String content, boolean isHttpOnly) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).httpOnly(isHttpOnly).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: not known to be false
  }

  public ResponseEntity<String> goodNotSensitive(String theme, String content) {
    ResponseCookie cookie = ResponseCookie.from("theme", theme).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: not a sensitive cookie
  }

  public ResponseEntity<String> goodCsrf(String csrfToken, String content) {
    ResponseCookie cookie = ResponseCookie.from("XSRF-TOKEN", csrfToken).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: CSRF cookies are read by JavaScript
  }

  public ResponseEntity<String> goodRemoval(String content) {
    ResponseCookie cookie = ResponseCookie.from("SESSION", "").path(COOKIE_PATH).maxAge(0).build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content); // GOOD: deletes the cookie
  }

  private static ResponseCookie buildSecureCookie(String cookieName, String value) {
    return ResponseCookie.from(cookieName, value).path(COOKIE_PATH).secure(true).build();
  }

  private static ResponseCookie buildHttpOnlyCookie(String cookieName, String value) {
    return ResponseCookie.from(cookieName, value).path(COOKIE_PATH).httpOnly(true).build();
  }
}
