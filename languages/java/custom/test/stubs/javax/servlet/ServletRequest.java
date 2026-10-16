package javax.servlet;

import java.io.IOException;

public interface ServletRequest {
  String getParameter(String name);

  String getContentType();

  ServletInputStream getInputStream() throws IOException;
}
