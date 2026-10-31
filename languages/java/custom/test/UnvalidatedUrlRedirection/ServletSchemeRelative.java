import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ServletSchemeRelative implements Filter {
  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    String loginType = request.getParameter("logintype"); // $ Source
    if (loginType == null) {
      response.sendRedirect("/login");
    } else if ("sessionfixation".equals(loginType)) {
      // GOOD: the parameter is known to be a constant.
      response.sendRedirect("/" + loginType + "/login");
    } else {
      // easybuggy: "/" + "/evil.example" yields the scheme-relative URL "//evil.example".
      response.sendRedirect("/" + loginType + "/login"); // $ Alert
    }
    chain.doFilter(req, res);
  }

  public void safe(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String loginType = request.getParameter("logintype");
    // GOOD: a non-empty path segment fixes the host.
    response.sendRedirect("/app/" + loginType);
    // GOOD: the parameter is only used in the query string.
    response.sendRedirect("/login?type=" + loginType);
    // GOOD: the parameter follows a context path and a query separator.
    response.sendRedirect(request.getContextPath() + "/login?next=" + loginType);
  }
}
