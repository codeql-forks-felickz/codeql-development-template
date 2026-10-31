import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

class VulnerableLogin extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (checkCredentials(request.getParameter("username"), request.getParameter("password"))) {
      HttpSession session = request.getSession(); // $ Alert
      session.setAttribute("isLoggedIn", "1");
      session.setAttribute("user", request.getParameter("username"));
      response.sendRedirect("home.jsp");
    }
  }

  static boolean checkCredentials(String user, String password) {
    return user != null && password != null;
  }
}

class VulnerableInlineLogin extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (VulnerableLogin.checkCredentials(request.getParameter("u"), request.getParameter("p"))) {
      request.getSession(true).setAttribute("authenticatedUser", request.getParameter("u")); // $ Alert
    }
  }
}

class SafeLoginChangeSessionId extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (VulnerableLogin.checkCredentials(request.getParameter("u"), request.getParameter("p"))) {
      request.changeSessionId();
      HttpSession session = request.getSession();
      session.setAttribute("user", request.getParameter("u"));
    }
  }
}

class SafeLoginInvalidate extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (VulnerableLogin.checkCredentials(request.getParameter("u"), request.getParameter("p"))) {
      HttpSession old = request.getSession(false);
      if (old != null) {
        old.invalidate();
      }
      HttpSession session = request.getSession(true);
      session.setAttribute("user", request.getParameter("u"));
    }
  }
}

class SafeNonAuthAttribute extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession();
    session.setAttribute("theme", request.getParameter("theme"));
    session.setAttribute("cart", request.getParameter("item"));
  }
}

class SafeReadOnly extends HttpServlet {
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession(false);
    if (session != null && session.getAttribute("user") != null) {
      response.sendRedirect("home.jsp");
    }
  }
}
