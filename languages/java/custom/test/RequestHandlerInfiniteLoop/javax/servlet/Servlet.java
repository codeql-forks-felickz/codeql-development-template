package javax.servlet;

public interface Servlet {
  void service(ServletRequest req, ServletResponse res) throws ServletException, java.io.IOException;
}
