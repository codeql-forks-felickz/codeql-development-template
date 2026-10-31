package app;

import java.io.IOException;
import java.sql.SQLException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ErrorServlet extends HttpServlet {

  private static void query(String user) throws SQLException {
    throw new SQLException("ORA-00942: table or view does not exist");
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    String mode = req.getParameter("mode");
    try {
      query(req.getParameter("user"));
    } catch (SQLException e) {
      if ("trace".equals(mode)) {
        // Already reported by the upstream java/stack-trace-exposure query.
        e.printStackTrace(resp.getWriter()); // $ Alert
      } else if ("message".equals(mode)) {
        resp.getWriter().println("Error: " + e.getMessage()); // $ Alert
      } else if ("sendError".equals(mode)) {
        resp.sendError(500, e.getMessage()); // $ Alert
      } else {
        resp.getWriter().println("An internal error occurred");
      }
    }
  }
}
