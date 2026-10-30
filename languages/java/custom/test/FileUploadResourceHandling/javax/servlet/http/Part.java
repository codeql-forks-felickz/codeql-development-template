package javax.servlet.http;

import java.io.IOException;
import java.io.InputStream;

public interface Part {
  InputStream getInputStream() throws IOException;

  String getName();

  String getSubmittedFileName();

  void write(String fileName) throws IOException;
}
