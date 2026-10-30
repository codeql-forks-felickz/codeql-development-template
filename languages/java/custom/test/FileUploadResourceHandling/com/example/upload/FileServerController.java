package com.example.upload;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import javax.servlet.http.Part;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

/**
 * Reduced from a file server: uploads are stored in a directory configured by a property that a
 * separate `WebMvcConfigurer` publishes as static web content, so any uploaded file type (for
 * example `.html` or `.svg`) is served inline from the application's origin.
 */
@Controller
public class FileServerController {
  @Value("${fileserver.location}")
  private String fileLocation;

  @Value("${archive.location}")
  private String archiveLocation;

  @Value("${private.location:/WEB-INF/uploads}")
  private String privateLocation;

  // BAD: the destination directory is served under `/files/**`.
  @RequestMapping(value = "/fileupload", method = RequestMethod.POST)
  public String importFile(@RequestParam("file") MultipartFile multipartFile, String username)
      throws IOException {
    File destinationDir = new File(fileLocation, username);
    destinationDir.mkdirs();
    try (InputStream is = multipartFile.getInputStream()) {
      java.nio.file.Path destinationFile =
          destinationDir.toPath().resolve(multipartFile.getOriginalFilename()); // $ Source
      Files.copy(is, destinationFile); // $ Alert
    }
    return "files";
  }

  // GOOD (for this query): the archive directory is not published as web content.
  @RequestMapping(value = "/archive", method = RequestMethod.POST)
  public String archiveFile(@RequestParam("file") MultipartFile multipartFile, String username)
      throws IOException {
    File destinationDir = new File(archiveLocation, username);
    try (InputStream is = multipartFile.getInputStream()) {
      Files.copy(is, destinationDir.toPath().resolve(multipartFile.getOriginalFilename()));
    }
    return "archived";
  }

  // BAD: this servlet-private location is explicitly published by Spring MVC.
  public void uploadToPublishedPrivateDirectory(Part part) throws IOException {
    part.write(privateLocation + "/" + part.getSubmittedFileName()); // $ Alert
  }
}
