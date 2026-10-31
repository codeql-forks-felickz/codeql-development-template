package javax.servlet.http;

import javax.servlet.ServletRequest;

public interface HttpServletRequest extends ServletRequest {
  String getRequestURI();

  StringBuffer getRequestURL();

  String getServletPath();

  String getPathInfo();

  String getMethod();
}
