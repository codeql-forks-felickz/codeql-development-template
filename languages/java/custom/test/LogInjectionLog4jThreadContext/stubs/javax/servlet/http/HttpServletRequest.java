package javax.servlet.http;

public interface HttpServletRequest {
  String getHeader(String name);

  String getParameter(String name);

  String getRemoteAddr();
}
