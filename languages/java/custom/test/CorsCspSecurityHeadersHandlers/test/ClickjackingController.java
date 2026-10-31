package test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Reduced from a controller whose handlers set framing protection inconsistently (CWE-1021).
@RestController
public class ClickjackingController {
  // BAD: unlike the other handlers, this one sets no framing protection.
  @GetMapping("/level1")
  public ResponseEntity<String> noFramingProtection() { // $ Alert
    return ResponseEntity.ok("vulnerable");
  }

  @GetMapping("/level2")
  public ResponseEntity<String> xFrameOptionsAllowAll() {
    HttpHeaders headers = new HttpHeaders();
    // BAD: ALLOWALL is not a valid X-Frame-Options value.
    headers.add("X-Frame-Options", "ALLOWALL"); // $ Alert
    return ResponseEntity.ok().headers(headers).body("vulnerable");
  }

  // GOOD: DENY.
  @GetMapping("/level4")
  public ResponseEntity<String> xFrameOptionsDeny() {
    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Frame-Options", "DENY");
    return ResponseEntity.ok().headers(headers).body("protected");
  }

  // GOOD: CSP frame-ancestors 'none'.
  @GetMapping("/level5")
  public ResponseEntity<String> cspFrameAncestorsNone() {
    return ResponseEntity.ok()
        .header("Content-Security-Policy", "frame-ancestors 'none'")
        .body("protected");
  }

  // GOOD: framing protection set by a helper.
  @GetMapping("/level6")
  public ResponseEntity<String> viaHelper() {
    return ResponseEntity.ok().headers(protectedHeaders()).body("protected");
  }

  private HttpHeaders protectedHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.set("X-Frame-Options", "SAMEORIGIN");
    return headers;
  }

  // GOOD: not a request handler.
  public String helper() {
    return "helper";
  }
}
