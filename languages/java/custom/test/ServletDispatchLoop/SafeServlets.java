import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// GOOD: the forward to itself only happens until a request attribute marks the request as
// already dispatched.
@WebServlet("/guarded")
class GuardedForwardServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    if (req.getAttribute("dispatched") == null) {
      req.getRequestDispatcher("/guarded").forward(req, res);
    }
  }
}

// GOOD: forwards to a different resource that does not dispatch back.
@WebServlet("/start")
class ForwardToViewServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/WEB-INF/view.jsp").forward(req, res);
  }
}

// GOOD: forwards to a servlet that only forwards to a view.
@WebServlet("/step1")
class ChainServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("/start").forward(req, res);
  }
}

// GOOD: the dispatch path depends on the request, so the loop is not certain.
@WebServlet("/dynamic")
class DynamicForwardServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    String next = req.getParameter("next");
    if (next == null) {
      next = "/start";
    }
    req.getRequestDispatcher(next).forward(req, res);
  }
}

// GOOD: the self-forward is only on one branch of a switch.
@WebServlet("/switch")
class SwitchForwardServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    switch (req.getParameter("mode")) {
      case "retry":
        req.getRequestDispatcher("/switch").forward(req, res);
        break;
      default:
        req.getRequestDispatcher("/start").forward(req, res);
    }
  }
}

// GOOD: the self-forward is only in an exception handler.
@WebServlet("/onerror")
class CatchForwardServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    try {
      req.getRequestDispatcher("/start").forward(req, res);
    } catch (IOException e) {
      req.getRequestDispatcher("/onerror").forward(req, res);
    }
  }
}

// GOOD: the self-forward is skipped by an early return once the request was dispatched.
@WebServlet("/early")
class EarlyReturnServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    if (req.getAttribute("dispatched") != null) {
      return;
    }
    req.getRequestDispatcher("/early").forward(req, res);
  }
}

// GOOD: a relative path is resolved against the current request path, so it is not matched.
@WebServlet("/relative")
class RelativeForwardServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    req.getRequestDispatcher("other").forward(req, res);
  }
}
