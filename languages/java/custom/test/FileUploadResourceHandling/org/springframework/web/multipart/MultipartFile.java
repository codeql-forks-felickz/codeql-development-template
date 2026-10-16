package org.springframework.web.multipart;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

public interface MultipartFile {
  String getName();

  String getOriginalFilename();

  String getContentType();

  boolean isEmpty();

  long getSize();

  byte[] getBytes() throws IOException;

  InputStream getInputStream() throws IOException;

  void transferTo(File dest) throws IOException, IllegalStateException;

  default void transferTo(Path dest) throws IOException, IllegalStateException {}
}
