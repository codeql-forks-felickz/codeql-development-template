package javax.servlet.http;

import javax.servlet.ServletException;

public abstract class HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, java.io.IOException {}
}
