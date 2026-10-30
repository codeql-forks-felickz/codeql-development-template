import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class ProfileController {
    private final String uploadDir = "/var/app/resources/images";

    private String storedUsername = "alice";

    @RequestMapping("/profile")
    public String processProfile(
            @RequestParam(value = "username", required = true) String username, // $ Source
            @RequestParam(value = "file", required = false) MultipartFile file)
            throws IOException {
        String extension = ".png";

        // String concatenation into `new File(String)` then `MultipartFile.transferTo(File)`
        String path = uploadDir + File.separator + username + extension;
        file.transferTo(new File(path)); // $ Alert

        File dest = new File(uploadDir + "/" + username + ".png");
        file.transferTo(dest); // $ Alert

        // `new File(File, String)` child argument
        file.transferTo(new File(new File(uploadDir), username + ".png")); // $ Alert

        // `MultipartFile.transferTo(Path)`
        file.transferTo(Paths.get(uploadDir, username + ".png")); // $ Alert
        file.transferTo(Paths.get(uploadDir).resolve(username + ".png")); // $ Alert

        // Already detected without custom models: `File` constructor summary into a built-in sink
        new FileOutputStream(new File(uploadDir + "/" + username + ".png")).close(); // $ Alert

        return "profile";
    }

    @RequestMapping("/profile/update")
    public String updateProfile(
            @RequestParam(value = "username", required = true) String username, // $ Source
            @RequestParam(value = "file", required = false) MultipartFile file) // $ Source
            throws IOException {
        // An equality check on one branch does not sanitize the merged path below
        if (!username.equals(storedUsername)) {
            storedUsername = username.toLowerCase();
        }

        if (file != null && !file.isEmpty()) {
            String extension = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf(".")); // $ Source
            String path = uploadDir + File.separator + username + extension;
            file.transferTo(new File(path)); // $ Alert
        }

        return "profile";
    }

    @RequestMapping("/profile/safe")
    public String processProfileSafe(
            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "file", required = false) MultipartFile file)
            throws IOException {
        // Constant destination: not tainted
        file.transferTo(new File(uploadDir + "/avatar.png"));

        // Value that does not come from the request: not a source
        file.transferTo(new File(uploadDir + "/" + storedUsername + ".png"));

        // Path traversal check sanitizes the request value
        if (username.contains("..") || username.contains("/") || username.contains("\\")) {
            return "error";
        }
        file.transferTo(new File(uploadDir + "/" + username + ".png"));

        return "profile";
    }
}
