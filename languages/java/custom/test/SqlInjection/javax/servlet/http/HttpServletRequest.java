package javax.servlet.http;

public interface HttpServletRequest {
  String getParameter(String name);

  String getMethod();

  HttpSession getSession();
}
