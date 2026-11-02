import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ServletRedirect {
  // AltoroJ (customize.jsp): a scheme check is not an allowlist. The standard query already
  // reports this pattern in Java source; the original finding is in a JSP scriptlet.
  public void customize(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String content = request.getParameter("content"); // $ Source
    if (content != null && !content.equalsIgnoreCase("customize.jsp")) {
      if (content.startsWith("http://") || content.startsWith("https://")) {
        response.sendRedirect(content); // $ Alert
      }
    }
  }

  // VulnerableApp (servlet variant): value written directly to the Location header.
  public void location(HttpServletRequest request, HttpServletResponse response) {
    String returnTo = request.getParameter("returnTo"); // $ Source
    response.setHeader("Location", returnTo); // $ Alert
  }
}
