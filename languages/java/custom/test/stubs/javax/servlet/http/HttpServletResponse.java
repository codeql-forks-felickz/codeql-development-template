package javax.servlet.http;

import javax.servlet.ServletResponse;

public interface HttpServletResponse extends ServletResponse {
  void setHeader(String name, String value);

  void addHeader(String name, String value);
}
