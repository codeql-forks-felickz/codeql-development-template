import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import javax.servlet.http.HttpServletRequest;

// Servlet form of a "URL preview" JSP scriptlet. The stock `java/ssrf` query already
// reports this pattern in `.java` sources; the same code inside a `.jsp` file is not
// extracted by the CodeQL Java extractor, so it is not analyzed there.
public class UrlPreview {

  private static final String ALLOWED_HOST = "https://example.com/";

  // BAD: the request parameter is used as the full URL that the server fetches.
  public InputStream preview(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url"); // $ Source
    URL u = new URL(target);
    URLConnection conn = u.openConnection(); // $ Alert
    return conn.getInputStream();
  }

  // GOOD: the request parameter only controls the path under a fixed host.
  public InputStream fixedHost(HttpServletRequest request) throws Exception {
    URL u = new URL(ALLOWED_HOST + request.getParameter("path"));
    return u.openConnection().getInputStream();
  }
}
