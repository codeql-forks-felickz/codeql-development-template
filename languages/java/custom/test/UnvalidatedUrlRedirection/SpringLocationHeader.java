import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SpringLocationHeader {
  private static final String LOCATION_HEADER_KEY = "Location";
  private static final List<String> ALLOWED = Arrays.asList("/", "/app/");

  // VulnerableApp: value added to the list returned for the "Location" key.
  private ResponseEntity<?> redirectTo(String urlToRedirect) {
    MultiValueMap<String, String> headerParam = new HttpHeaders();
    headerParam.put(LOCATION_HEADER_KEY, new ArrayList<>());
    headerParam.get(LOCATION_HEADER_KEY).add(urlToRedirect); // $ Alert
    return new ResponseEntity<>(headerParam, HttpStatus.FOUND);
  }

  @GetMapping("/level1")
  public ResponseEntity<?> level1(@RequestParam("returnTo") String urlToRedirect) { // $ Source
    return this.redirectTo(urlToRedirect);
  }

  @GetMapping("/add")
  public ResponseEntity<?> add(@RequestParam("returnTo") String url) { // $ Source
    HttpHeaders headers = new HttpHeaders();
    headers.add("Location", url); // $ Alert
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
  }

  @GetMapping("/set")
  public ResponseEntity<?> set(@RequestParam("returnTo") String url) { // $ Source
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.LOCATION, url); // $ Alert
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
  }

  @GetMapping("/put")
  public ResponseEntity<?> put(@RequestParam("returnTo") String url) { // $ Source
    HttpHeaders headers = new HttpHeaders();
    headers.put("Location", Collections.singletonList(url)); // $ Alert
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
  }

  @GetMapping("/setLocation")
  public ResponseEntity<?> setLocation(@RequestParam("returnTo") String url) { // $ Source
    HttpHeaders headers = new HttpHeaders();
    headers.setLocation(URI.create(url)); // $ Alert
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
  }

  @GetMapping("/builderLocation")
  public ResponseEntity<?> builderLocation(@RequestParam("returnTo") String url) { // $ Source
    return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build(); // $ Alert
  }

  @GetMapping("/builderHeader")
  public ResponseEntity<?> builderHeader(@RequestParam("returnTo") String url) { // $ Source
    return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build(); // $ Alert
  }

  // GOOD: the value is written to a header other than "Location".
  @GetMapping("/otherHeader")
  public ResponseEntity<?> otherHeader(@RequestParam("returnTo") String url) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Return-To", url);
    headers.get("X-Other").add(url);
    return ResponseEntity.status(HttpStatus.OK).header("X-Return-To", url).build();
  }

  // GOOD: the destination is checked against an allowlist.
  @GetMapping("/allowlisted")
  public ResponseEntity<?> allowlisted(@RequestParam("returnTo") String url) {
    HttpHeaders headers = new HttpHeaders();
    if (ALLOWED.contains(url)) {
      headers.add("Location", url);
    }
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
  }
}
