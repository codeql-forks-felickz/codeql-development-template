package javax.servlet.http;

import javax.servlet.ServletResponse;

public interface HttpServletResponse extends ServletResponse {
  void addCookie(Cookie cookie);

  void addHeader(String name, String value);

  void setHeader(String name, String value);
}
