package jakarta.servlet.http;

import java.io.IOException;

public interface Part {
    String getSubmittedFileName();

    void write(String fileName) throws IOException;
}
