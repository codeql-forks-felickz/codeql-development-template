package javax.servlet.http;

import javax.servlet.ServletResponse;

public interface HttpServletResponse extends ServletResponse {
  void sendRedirect(String location) throws java.io.IOException;

  void setHeader(String name, String value);

  String encodeRedirectURL(String url);
}
