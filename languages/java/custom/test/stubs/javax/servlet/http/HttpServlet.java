package javax.servlet.http;

import java.io.IOException;
import javax.servlet.ServletException;

public abstract class HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {}
}
