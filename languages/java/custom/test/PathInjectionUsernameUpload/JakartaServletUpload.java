import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;

public class JakartaServletUpload {
    private final String uploadDir = "/var/app/uploads";

    public void doPost(HttpServletRequest request) throws IOException {
        String username = request.getParameter("username"); // $ Source
        Part part = request.getPart("file");

        part.write(uploadDir + "/" + username + ".png"); // $ Alert

        part.write(uploadDir + "/avatar.png");
    }
}
