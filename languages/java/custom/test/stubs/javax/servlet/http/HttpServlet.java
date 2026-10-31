package javax.servlet.http;

public abstract class HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {}

  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {}
}
