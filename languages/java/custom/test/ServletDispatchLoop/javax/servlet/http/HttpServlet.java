package javax.servlet.http;

import java.io.IOException;
import javax.servlet.Servlet;
import javax.servlet.ServletException;

public abstract class HttpServlet implements Servlet {
  protected void service(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {}

  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {}

  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {}
}
