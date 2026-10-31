package javax.servlet.http;

import javax.servlet.ServletRequest;

public interface HttpServletRequest extends ServletRequest {
  String getRequestURI();

  String getQueryString();

  String getContextPath();
}
