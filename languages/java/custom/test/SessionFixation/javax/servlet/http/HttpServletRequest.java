package javax.servlet.http;

public interface HttpServletRequest {
  String getParameter(String name);

  HttpSession getSession();

  HttpSession getSession(boolean create);

  String changeSessionId();
}
