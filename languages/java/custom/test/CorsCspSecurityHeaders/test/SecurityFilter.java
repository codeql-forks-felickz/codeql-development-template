package test;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Reduced from a servlet filter that skips framing protection for one path (CWE-1021).
public class SecurityFilter implements Filter {
  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    String target = request.getRequestURI();

    // BAD: framing protection is skipped for a request path.
    if (!target.startsWith("/admins/clickjacking")) {
      response.addHeader("X-FRAME-OPTIONS", "DENY"); // $ Alert
    }
    response.addHeader("X-Content-Type-Options", "nosniff");
    // GOOD: X-XSS-Protection is not a framing header.
    if (!target.startsWith("/xss")) {
      response.addHeader("X-XSS-Protection", "1; mode=block");
    }
    chain.doFilter(req, res);
  }

  public void badServletPathCondition(HttpServletRequest request, HttpServletResponse response) {
    // BAD: frame-ancestors only applied to some paths.
    if (request.getServletPath().equals("/account")) {
      response.setHeader("Content-Security-Policy", "frame-ancestors 'none'"); // $ Alert
    }
  }

  public void badInvalidXFrameOptions(HttpServletResponse response) {
    // BAD: browsers do not recognize ALLOWALL, so the page can be framed.
    response.setHeader("X-Frame-Options", "ALLOWALL"); // $ Alert
    // BAD: ALLOW-FROM is obsolete and ignored by modern browsers.
    response.setHeader("X-Frame-Options", "ALLOW-FROM https://partner.example.com"); // $ Alert
  }

  public void badWildcardFrameAncestors(HttpServletResponse response) {
    // BAD: any origin may frame the page.
    response.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors *"); // $ Alert
  }

  public void badSchemeWildcardFrameAncestors(HttpServletResponse response) {
    // BAD: any HTTPS site may frame the page.
    response.setHeader("Content-Security-Policy", "frame-ancestors https://*"); // $ Alert
  }

  public void goodStricterForOnePath(HttpServletRequest request, HttpServletResponse response) {
    // GOOD: every path is protected; one path gets a stricter value.
    response.setHeader("X-Frame-Options", "SAMEORIGIN");
    if (request.getRequestURI().startsWith("/admin")) {
      response.setHeader("X-Frame-Options", "DENY");
    }
  }

  public void goodBothBranches(HttpServletRequest request, HttpServletResponse response) {
    // GOOD: both branches set framing protection.
    if (request.getRequestURI().startsWith("/embed")) {
      response.setHeader("Content-Security-Policy", "frame-ancestors 'self' https://partner.example.com");
    } else {
      response.setHeader("X-Frame-Options", "DENY");
    }
  }

  public void goodUnconditional(HttpServletRequest request, HttpServletResponse response) {
    // GOOD: framing protection applied regardless of the path.
    response.setHeader("X-Frame-Options", "sameorigin");
    response.setHeader("Content-Security-Policy", "frame-ancestors 'self' https://partner.example.com");
  }

  public void goodNonPathCondition(HttpServletRequest request, HttpServletResponse response) {
    // GOOD: the condition does not depend on the request path.
    if (response != null) {
      response.setHeader("X-Frame-Options", "DENY");
    }
  }
}
