import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ServletCookies {
  public void bad(HttpServletResponse response, String sessionId) {
    Cookie c = new Cookie("SESSION", sessionId);
    response.addCookie(c); // BAD: existing behavior, no setSecure(true)
  }

  public void badFalse(HttpServletResponse response, String sessionId) {
    Cookie c = new Cookie("SESSION", sessionId);
    c.setSecure(false);
    response.addCookie(c); // BAD: existing behavior
  }

  public void good(HttpServletResponse response, String sessionId) {
    Cookie c = new Cookie("SESSION", sessionId);
    c.setSecure(true);
    response.addCookie(c); // GOOD
  }

  public void goodIsSecure(
      HttpServletRequest request, HttpServletResponse response, String sessionId) {
    Cookie c = new Cookie("SESSION", sessionId);
    c.setSecure(request.isSecure());
    response.addCookie(c); // GOOD
  }

  public void badRawHeader(HttpServletResponse response, String sessionId) {
    response.addHeader("Set-Cookie", "SESSION=" + sessionId + "; Path=/; HttpOnly"); // BAD
  }

  public void badRawHeaderSet(HttpServletResponse response, String sessionId) {
    String header = "SESSION=" + sessionId + "; Path=/";
    response.setHeader("set-cookie", header); // BAD
  }

  public void goodRawHeader(HttpServletResponse response, String sessionId) {
    response.addHeader("Set-Cookie", "SESSION=" + sessionId + "; Path=/; Secure; HttpOnly"); // GOOD
  }

  public void goodRawHeaderLowercase(HttpServletResponse response, String sessionId) {
    response.addHeader("Set-Cookie", "SESSION=" + sessionId + ";secure"); // GOOD
  }

  public void goodRawHeaderUnknown(HttpServletResponse response, String headerValue) {
    response.addHeader("Set-Cookie", headerValue); // GOOD: value not built here
  }

  public void goodOtherHeader(HttpServletResponse response, String value) {
    response.addHeader("X-Custom", "a=" + value); // GOOD: not a Set-Cookie header
  }
}
