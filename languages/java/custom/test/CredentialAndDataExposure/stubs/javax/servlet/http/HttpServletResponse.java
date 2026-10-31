package javax.servlet.http;

public interface HttpServletResponse {
  void sendRedirect(String location) throws java.io.IOException;
}
