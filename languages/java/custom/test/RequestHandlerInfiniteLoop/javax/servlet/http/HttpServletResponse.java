package javax.servlet.http;

public interface HttpServletResponse extends javax.servlet.ServletResponse {
  java.io.PrintWriter getWriter() throws java.io.IOException;

  void flushBuffer() throws java.io.IOException;
}
