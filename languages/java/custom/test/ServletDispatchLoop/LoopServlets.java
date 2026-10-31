import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// BAD: `include` to a path covered by the servlet's own wildcard mapping.
@WebServlet("/report/*")
class IncludeSelfServlet extends HttpServlet {
  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    try {
      req.getRequestDispatcher("/report/header?x=1").include(req, res); // $ Alert
    } finally {
      res.toString();
    }
  }
}

// BAD: two servlets that unconditionally forward to each other.
@WebServlet("/ping")
class PingServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/pong").forward(req, res); // $ Alert
  }
}

@WebServlet("/pong")
class PongServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/ping").forward(req, res); // $ Alert
  }
}

// BAD: mapped in `web.xml` rather than with an annotation.
class XmlMappedLoopServlet extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/xmlloop").forward(req, res); // $ Alert
  }
}
