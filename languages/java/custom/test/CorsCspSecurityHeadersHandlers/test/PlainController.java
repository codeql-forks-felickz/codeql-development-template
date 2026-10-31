package test;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// GOOD: no handler in this controller sets framing headers, so protection is presumably global.
@RestController
public class PlainController {
  @GetMapping("/a")
  public ResponseEntity<String> a() {
    return ResponseEntity.ok("a");
  }

  @GetMapping("/b")
  public ResponseEntity<String> b() {
    return ResponseEntity.ok("b");
  }
}
