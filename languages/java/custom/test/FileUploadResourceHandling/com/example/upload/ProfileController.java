package com.example.upload;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletContext;
import javax.servlet.http.Part;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

/**
 * Reduced from a profile-image upload: the image is stored beneath the deployed web application's
 * resources directory, keeping the extension of the client-supplied file name.
 */
@Controller
public class ProfileController {
  private static final Set<String> ALLOWED_EXTENSIONS =
      new HashSet<>(Arrays.asList(".png", ".jpg", ".jpeg", ".gif"));

  @Autowired ServletContext context;

  // BAD: `.jsp` (or any other extension) is kept and the file is written under the web root.
  @RequestMapping(value = "/profile", method = RequestMethod.POST)
  public String processProfile(
      @RequestParam(value = "username") String username,
      @RequestParam(value = "file", required = false) MultipartFile file) {
    if (file != null && !file.isEmpty()) {
      String imageDir = context.getRealPath("/resources/images") + File.separator;
      try {
        String extension =
            file.getOriginalFilename() // $ Source
                .substring(file.getOriginalFilename().lastIndexOf("."));
        String path = imageDir + username + extension;
        file.transferTo(new File(path)); // $ Alert
      } catch (IllegalStateException | IOException ex) {
        return "error";
      }
    }
    return "ok";
  }

  // GOOD: the extension is checked against an allowlist before the file is written.
  @RequestMapping(value = "/profileAllowlist", method = RequestMethod.POST)
  public String processProfileAllowlist(
      @RequestParam(value = "username") String username,
      @RequestParam(value = "file") MultipartFile file)
      throws IOException {
    String imageDir = context.getRealPath("/resources/images") + File.separator;
    String name = file.getOriginalFilename();
    String extension = name.substring(name.lastIndexOf(".")).toLowerCase();
    if (!ALLOWED_EXTENSIONS.contains(extension)) {
      return "error";
    }
    file.transferTo(new File(imageDir + username + extension));
    return "ok";
  }

  // GOOD: the server decides the extension.
  @RequestMapping(value = "/profileFixedExtension", method = RequestMethod.POST)
  public String processProfileFixedExtension(
      @RequestParam(value = "username") String username,
      @RequestParam(value = "file") MultipartFile file)
      throws IOException {
    String imageDir = context.getRealPath("/resources/images") + File.separator;
    file.transferTo(new File(imageDir + username.hashCode() + ".png"));
    return "ok";
  }

  // BAD: Servlet `Part` upload written under the web root with the submitted file name.
  public void servletPartUpload(Part part) throws IOException {
    String uploads = context.getRealPath("/uploads");
    part.write(uploads + File.separator + part.getSubmittedFileName()); // $ Alert
  }

  // GOOD: the submitted file name must end with `.png`.
  public void servletPartUploadChecked(Part part) throws IOException {
    String uploads = context.getRealPath("/uploads");
    String name = part.getSubmittedFileName();
    if (name.endsWith(".png")) {
      part.write(uploads + File.separator + name);
    }
  }

  // GOOD: the checked terminal extension belongs to the unchanged submitted filename.
  public void servletPartUploadCheckedOriginalName(Part part) throws IOException {
    String uploads = context.getRealPath("/uploads");
    String name = part.getSubmittedFileName();
    String extension = name.substring(name.lastIndexOf("."));
    if (!ALLOWED_EXTENSIONS.contains(extension)) {
      return;
    }
    part.write(uploads + File.separator + name);
  }

  // BAD: rejecting allowlisted extensions leaves other extensions writable.
  public void servletPartUploadRejectsAllowlist(Part part) throws IOException {
    String uploads = context.getRealPath("/uploads");
    String name = part.getSubmittedFileName(); // $ Source
    String extension = name.substring(name.lastIndexOf("."));
    if (ALLOWED_EXTENSIONS.contains(extension)) {
      return;
    }
    part.write(uploads + File.separator + name); // $ Alert
  }

  // GOOD: servlet-private directories are not directly web-accessible.
  public void servletPartUploadToPrivateDirectory(Part part) throws IOException {
    part.write(
        context.getRealPath("/WEB-INF/uploads")
            + File.separator
            + part.getSubmittedFileName());
  }

  // GOOD: the source web directory excludes protected servlet locations.
  public void servletPartUploadToPrivateWebappDirectory(Part part) throws IOException {
    part.write("src/main/webapp/META-INF/uploads/" + part.getSubmittedFileName());
  }
}
