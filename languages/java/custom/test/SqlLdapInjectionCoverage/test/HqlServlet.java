package test;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.hibernate.Query;
import org.hibernate.Session;

// Java equivalent of an HQL query built by concatenating a request parameter.
public class HqlServlet extends HttpServlet {
  private Session session;

  private static Object queryUsers(Session session, String id) {
    Query query = session.createQuery("from Users where id=" + id); // $ Alert[java/sql-injection]
    return query.list();
  }

  private static Object queryUsersSafe(Session session, String id) {
    Query query = session.createQuery("from Users where id=:id");
    query.setParameter("id", id);
    return query.list();
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    queryUsers(session, req.getParameter("id")); // $ Source[java/sql-injection]
    queryUsersSafe(session, req.getParameter("id"));
  }
}
