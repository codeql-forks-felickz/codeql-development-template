package test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// GOOD: CspHeaderFilter applies frame-ancestors to every response, so the handler without its own
// framing header is still protected.
@RestController
public class GlobalFilteredController {
  @GetMapping("/plain")
  public ResponseEntity<String> plain() {
    return ResponseEntity.ok("plain");
  }

  @GetMapping("/strict")
  public ResponseEntity<String> strict() {
    HttpHeaders headers = new HttpHeaders();
    headers.set("X-Frame-Options", "DENY");
    return ResponseEntity.ok().headers(headers).body("strict");
  }
}
