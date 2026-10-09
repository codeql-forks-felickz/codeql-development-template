package org.springframework.web.multipart;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public interface MultipartFile {
    String getName();

    String getOriginalFilename();

    boolean isEmpty();

    void transferTo(File dest) throws IOException, IllegalStateException;

    default void transferTo(Path dest) throws IOException, IllegalStateException {}
}
