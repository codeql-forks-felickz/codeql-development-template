package javax.servlet.http;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public abstract class HttpServlet implements Servlet {
  public void service(ServletRequest req, ServletResponse res)
      throws ServletException, java.io.IOException {}

  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, java.io.IOException {}

  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, java.io.IOException {}
}
