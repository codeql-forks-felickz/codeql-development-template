package com.example.upload;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Random;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.servlet.http.Part;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

/**
 * Reduced from an "unrestricted file upload" lab: uploads are copied into the `static/upload`
 * classpath directory, which Spring Boot serves as public web content.
 */
@Controller
public class StaticUploadController {
  private static final String BASE_PATH = "static";
  private static final Random RANDOM = new Random();
  private static final Pattern ENDS_WITH_HTML = Pattern.compile("^.+\\.html$");
  private static final Pattern ENDS_WITH_PNG_OR_JPEG = Pattern.compile("^.+\\.(png|jpeg)$");
  private static final Pattern CONTAINS_PNG_OR_JPEG = Pattern.compile("^.+\\.(png|jpeg)");

  private Path root;

  public StaticUploadController() throws IOException, URISyntaxException {
    URI uploadDirectoryURI =
        new URI(
            Thread.currentThread().getContextClassLoader().getResource(BASE_PATH).toURI()
                + "/upload");
    root = Paths.get(uploadDirectoryURI);
  }

  private static String store(Path root, String fileName, MultipartFile file) throws IOException {
    Files.copy(
        file.getInputStream(),
        root.resolve(fileName), // $ Alert
        StandardCopyOption.REPLACE_EXISTING);
    return "/upload/" + fileName;
  }

  private static void writeBytes(byte[] bytes, Path destination) throws IOException {
    Files.write(destination, bytes); // $ Alert
  }

  // BAD: client-supplied name (and extension) is used as-is.
  @RequestMapping(value = "/level1", method = RequestMethod.POST)
  public String level1(@RequestParam("file") MultipartFile file) throws IOException {
    return store(root, file.getOriginalFilename(), file); // $ Source
  }

  // BAD: a random prefix does not change the attacker-controlled extension.
  @RequestMapping(value = "/level2", method = RequestMethod.POST)
  public String level2(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = RANDOM.nextInt() + "_" + file.getOriginalFilename(); // $ Source
    return store(root, fileName, file);
  }

  // BAD: a deny-list of `.html` still allows `.htm`, `.svg`, `.jsp`, ...
  @RequestMapping(value = "/level3", method = RequestMethod.POST)
  public String level3(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename(); // $ Source
    if (ENDS_WITH_HTML.matcher(fileName).matches()) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // BAD: `find` on a non end-anchored pattern accepts `shell.png.jsp`.
  @RequestMapping(value = "/level4", method = RequestMethod.POST)
  public String level4(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename(); // $ Source
    if (!CONTAINS_PNG_OR_JPEG.matcher(fileName).find()) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // BAD: the allowlist checks the full name, but the stored name is truncated at a null byte, so
  // `shell.jsp<NUL>.png` passes the check and is stored as `shell.jsp`.
  @RequestMapping(value = "/level7", method = RequestMethod.POST)
  public String level7(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFileName;
    if (file.getOriginalFilename().contains("\u0000")) {
      originalFileName =
          file.getOriginalFilename() // $ Source
              .substring(0, file.getOriginalFilename().indexOf("\u0000"));
    } else {
      originalFileName = file.getOriginalFilename(); // $ Source
    }
    if (!ENDS_WITH_PNG_OR_JPEG.matcher(file.getOriginalFilename()).matches()) {
      return "Input is invalid";
    }
    return store(root, RANDOM.nextInt() + "_" + originalFileName, file);
  }

  // BAD: this only restricts the characters in the name, not its extension.
  @RequestMapping(value = "/characterOnlyRegex", method = RequestMethod.POST)
  public String characterOnlyRegex(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename(); // $ Source
    if (!fileName.matches("[A-Za-z0-9._-]+")) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // GOOD: the constant regex requires an approved extension at the end of the name.
  @RequestMapping(value = "/stringMatchesAllowlist", method = RequestMethod.POST)
  public String stringMatchesAllowlist(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();
    if (!fileName.matches("^.+\\.(png|jpeg)$")) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // GOOD: Pattern.matches applies the same end-anchored extension allowlist.
  @RequestMapping(value = "/patternMatchesAllowlist", method = RequestMethod.POST)
  public String patternMatchesAllowlist(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();
    if (!Pattern.matches("^.+\\.(png|jpeg)$", fileName)) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // BAD: upload content reaches Files.write through a helper call.
  public void uploadThroughHelper(MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename(); // $ Source
    Path destination =
        Paths.get("src/main/resources/static/uploads").resolve(fileName);
    writeBytes(file.getBytes(), destination);
  }

  // GOOD: a filename by itself does not make an arbitrary byte array an upload.
  public void writeNonUploadBytes(Part part) throws IOException {
    Path destination =
        Paths.get("src/main/resources/static/uploads").resolve(part.getSubmittedFileName());
    Files.write(destination, new byte[0]);
  }

  // GOOD: the fixed final extension prevents the client from choosing an active extension.
  public void uploadWithSafeSuffix(Part part) throws IOException {
    part.write(root.resolve(part.getSubmittedFileName() + ".png").toString());
  }

  // BAD: a fixed dangerous extension still permits active content.
  public void uploadWithDangerousSuffix(Part part) throws IOException {
    part.write(root.resolve(part.getSubmittedFileName() + ".jsp").toString()); // $ Alert
  }

  // BAD: written to the source web directory, which is packaged as web content.
  @RequestMapping(value = "/webapp", method = RequestMethod.POST)
  public String webappDirectory(@RequestParam("file") MultipartFile file) throws IOException {
    Path dest = Paths.get("src/main/webapp/uploads", file.getOriginalFilename()); // $ Source
    Files.write(dest, file.getBytes()); // $ Alert
    return "stored";
  }

  // GOOD: the whole file name must match an end-anchored allowlist.
  @RequestMapping(value = "/safeAllowlist", method = RequestMethod.POST)
  public String safeAllowlist(@RequestParam("file") MultipartFile file) throws IOException {
    String fileName = file.getOriginalFilename();
    if (!ENDS_WITH_PNG_OR_JPEG.matcher(fileName).matches()) {
      return "Input is invalid";
    }
    return store(root, fileName, file);
  }

  // GOOD: the stored name is generated by the server and the extension is derived from the
  // detected content type, not from the client.
  @RequestMapping(value = "/safeGenerated", method = RequestMethod.POST)
  public String safeGenerated(@RequestParam("file") MultipartFile file) throws IOException {
    String extension = detectImageExtension(file.getBytes());
    if (extension == null) {
      return "Input is invalid";
    }
    return store(root, UUID.randomUUID() + extension, file);
  }

  // GOOD (for this query): the upload is not stored under a web-accessible directory.
  @RequestMapping(value = "/safeOutsideWebRoot", method = RequestMethod.POST)
  public String safeOutsideWebRoot(@RequestParam("file") MultipartFile file) throws IOException {
    Path quarantine = Files.createTempDirectory("quarantine");
    Files.copy(file.getInputStream(), quarantine.resolve(file.getOriginalFilename()));
    return "stored";
  }

  private static String detectImageExtension(byte[] content) {
    if (content.length > 3 && content[0] == (byte) 0x89 && content[1] == 0x50) {
      return ".png";
    }
    if (content.length > 3 && content[0] == (byte) 0xFF && content[1] == (byte) 0xD8) {
      return ".jpeg";
    }
    return null;
  }
}
