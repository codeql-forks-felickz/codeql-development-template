# Unrestricted upload of file with dangerous type to a web-accessible directory

Web applications that let users upload files must control what is stored and where. If an uploaded file is written into a directory that the web server serves (for example `ServletContext.getRealPath(...)`, or Spring Boot's `static`/`public` classpath locations) and the stored file name or extension comes from the client (`MultipartFile.getOriginalFilename()`, `Part.getSubmittedFileName()`), an attacker can choose an extension such as `.jsp`, `.html` or `.svg`. Requesting the uploaded file afterwards can then execute code on the server or serve attacker-controlled active content to other users (CWE-434).

The query reports writes of uploaded file content (`MultipartFile.transferTo`, `Part.write`, `Files.copy`/`Files.write` with the upload's content) whose destination is both:

- derived from a web-accessible directory, and
- derived from the client-supplied file name, without an intervening allowlist check (for example `name.endsWith(".png")`, `ALLOWED.contains(ext)` or `PATTERN.matcher(name).matches()`).

Deny-list checks (for example rejecting only `.html`) and non end-anchored pattern checks using `Matcher.find()` are not considered validation, as they can be bypassed with other dangerous extensions or names such as `shell.png.jsp`.

## Recommendation

- Store uploads outside of the web root and serve them through a controller that sets a safe `Content-Type` and `Content-Disposition`.
- Generate the stored file name on the server (for example a random UUID) and derive the extension from the validated content type rather than from the client-supplied name.
- If the client-supplied extension must be kept, validate it against a strict allowlist of expected extensions.

## Example

The following controller keeps the client-supplied extension and writes the file under the web application's resources directory. Uploading `shell.jsp` creates a JSP page that the server executes when requested:

```java
@RequestMapping(value = "/profile", method = RequestMethod.POST)
public String processProfile(@RequestParam("username") String username,
                             @RequestParam("file") MultipartFile file) throws IOException {
  String imageDir = context.getRealPath("/resources/images") + File.separator;
  String extension =
      file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf("."));
  file.transferTo(new File(imageDir + username + extension)); // BAD
  return "ok";
}
```

The following version only accepts an allowlisted image extension:

```java
private static final Set<String> ALLOWED_EXTENSIONS = Set.of(".png", ".jpg", ".jpeg", ".gif");

@RequestMapping(value = "/profile", method = RequestMethod.POST)
public String processProfile(@RequestParam("username") String username,
                             @RequestParam("file") MultipartFile file) throws IOException {
  String imageDir = context.getRealPath("/resources/images") + File.separator;
  String name = file.getOriginalFilename();
  String extension = name.substring(name.lastIndexOf(".")).toLowerCase();
  if (!ALLOWED_EXTENSIONS.contains(extension)) {
    return "error";
  }
  file.transferTo(new File(imageDir + UUID.randomUUID() + extension)); // GOOD
  return "ok";
}
```

## Limitations

- Validation performed indirectly (for example inside a `Supplier<Boolean>` lambda evaluated by a shared helper) is not recognized and may be reported.
- The web-accessible directory and the client-supplied file name are tracked independently, so a shared helper that is called with both a web-accessible and a non web-accessible directory may be reported for callers that use the latter.
- Path traversal through the client-supplied name is outside the scope of this query (see `java/path-injection`).

## References

- OWASP: [Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload).
- OWASP: [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
