import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageProxyController {

  private static final Set<String> ALLOWED_URLS = null;

  // BAD: the URL is concatenated into a `sh -c` curl command line (the reported pattern).
  @GetMapping("/image")
  public String shellCurl(@RequestParam String url) throws Exception { // $ Source
    File out = new File("/tmp/img.jpg");
    String[] command = {"/bin/sh", "-c", "curl --silent -S " + url + " --max-time 10 --output " + out.getAbsolutePath()}; // $ Alert
    ProcessBuilder pb = new ProcessBuilder(command);
    pb.directory(new File("/home/"));
    pb.start().waitFor();
    return out.getPath();
  }

  // BAD: absolute program path in a shell string; the slash in `/usr/bin/` is not a host prefix.
  @GetMapping("/image2")
  public void shellCurlAbsolute(@RequestParam String url) throws Exception { // $ Source
    new ProcessBuilder("/bin/sh", "-c", "/usr/bin/curl -s " + url).start(); // $ Alert
  }

  // BAD: argv form. No shell is involved, so `java/command-line-injection` does not report it,
  // but curl still fetches whatever URL the caller supplies.
  @GetMapping("/image3")
  public void argvCurl(@RequestParam String url) throws Exception { // $ Source
    new ProcessBuilder("curl", "--silent", "-S", url).start(); // $ Alert
  }

  // BAD: wget through `Runtime.exec(String[])`.
  @GetMapping("/image4")
  public void argvWget(@RequestParam String url) throws Exception { // $ Source
    String[] cmd = {"/usr/bin/wget", "-q", "-O", "-", url}; // $ Alert
    Runtime.getRuntime().exec(cmd);
  }

  // BAD: single-string `Runtime.exec`, which is split on whitespace.
  @GetMapping("/image5")
  public void stringWget(@RequestParam String url) throws Exception { // $ Source
    Runtime.getRuntime().exec("wget -q -O - " + url); // $ Alert
  }

  // BAD: argument list.
  @GetMapping("/image6")
  public void listCurl(@RequestParam String url) throws Exception { // $ Source
    List<String> cmd = Arrays.asList("curl", "-s", url); // $ Alert
    new ProcessBuilder(cmd).start();
  }

  // GOOD: the request value only selects a path under a fixed host.
  @GetMapping("/thumb")
  public void fixedHostArgv(@RequestParam String name) throws Exception {
    new ProcessBuilder("curl", "-s", "https://images.example.com/thumbs/" + name).start();
  }

  // GOOD: fixed host inside a shell string.
  @GetMapping("/thumb2")
  public void fixedHostShell(@RequestParam String name) throws Exception {
    new ProcessBuilder("/bin/sh", "-c", "curl -s https://images.example.com/thumbs/" + name).start();
  }

  // GOOD: the URL is checked against an allowlist.
  @GetMapping("/image7")
  public void allowlisted(@RequestParam String url) throws Exception {
    if (!ALLOWED_URLS.contains(url)) {
      return;
    }
    new ProcessBuilder("curl", "-s", url).start();
  }

  // GOOD: not a URL-fetching program.
  @GetMapping("/convert")
  public void notFetch(@RequestParam String input) throws Exception {
    new ProcessBuilder("convert", input, "out.png").start();
  }

  // GOOD: constant URL.
  @GetMapping("/health")
  public void constantUrl() throws Exception {
    new ProcessBuilder("curl", "-s", "https://status.example.com/").start();
  }
}
