package javax.servlet.http;

public abstract class HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws javax.servlet.ServletException, java.io.IOException {}

  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws javax.servlet.ServletException, java.io.IOException {}
}
