package javax.servlet;

public interface ServletRequest {
  String getParameter(String name);

  Object getAttribute(String name);

  RequestDispatcher getRequestDispatcher(String path);
}
