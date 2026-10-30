import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.function.Supplier;
import org.springframework.web.multipart.MultipartFile;

// Upload handler that stores the file under a fixed root using the raw client-supplied
// original file name, via a shared helper that resolves the name against the root.
public class ContentDispositionUpload {
    private Path contentDispositionRoot = Paths.get("/content-disposition/");

    private Path root = Paths.get("/static/uploads/");

    private static String store(Path root, String fileName, Supplier<Boolean> validator, MultipartFile file)
            throws IOException {
        if (validator.get()) {
            Files.copy(file.getInputStream(), root.resolve(fileName), StandardCopyOption.REPLACE_EXISTING); // $ Alert
            return fileName;
        }
        return null;
    }

    public String uploadContentDisposition(MultipartFile file) throws IOException {
        return store(contentDispositionRoot, file.getOriginalFilename(), () -> true, file); // $ Source
    }

    public String uploadPrefixed(MultipartFile file) throws IOException {
        return store(root, System.nanoTime() + "_" + file.getOriginalFilename(), () -> true, file); // $ Source
    }

    public String uploadSafe(MultipartFile file) throws IOException {
        return store(root, java.util.UUID.randomUUID() + ".png", () -> true, file);
    }
}
