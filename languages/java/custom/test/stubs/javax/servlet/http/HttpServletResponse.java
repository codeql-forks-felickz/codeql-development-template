package javax.servlet.http;

import java.io.IOException;
import java.io.PrintWriter;

public interface HttpServletResponse {
  PrintWriter getWriter() throws IOException;

  void sendError(int sc, String msg) throws IOException;
}
