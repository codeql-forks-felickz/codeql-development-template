import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/exact-parent/*")
class BroadPathServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/exact-parent/view").forward(req, res);
  }
}

// GOOD: the exact mapping wins over the broader path mapping.
@WebServlet("/exact-parent/view")
class ExactPathServlet extends HttpServlet {}

// GOOD: the longest path-prefix mapping wins over the broader mapping.
@WebServlet("/prefix/*")
class BroadPrefixServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/prefix/item").forward(req, res);
  }
}

@WebServlet("/prefix/item/*")
class LongPrefixServlet extends HttpServlet {}

// GOOD: a path-prefix mapping wins over an extension mapping.
@WebServlet("*.view")
class ExtensionServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/views/home.view").forward(req, res);
  }
}

@WebServlet("/views/*")
class PathServlet extends HttpServlet {}
