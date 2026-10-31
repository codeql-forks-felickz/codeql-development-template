package test;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

// Reduced from a global response-header filter (CWE-693).
public class CspHeaderFilter implements Filter {
  private static final String SAFE_POLICY = "default-src 'self'; script-src 'self'";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (response instanceof HttpServletResponse) {
      HttpServletResponse httpResponse = (HttpServletResponse) response;
      // BAD: no script-src, so default-src allows inline scripts and eval.
      httpResponse.setHeader(
          "Content-Security-Policy",
          "frame-ancestors 'self'; form-action 'self'; "
              + "default-src 'unsafe-inline' 'unsafe-eval' 'self'; style-src 'unsafe-inline' 'self'"); // $ Alert
      httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    }
    chain.doFilter(request, response);
  }

  public void badScriptSrcInline(HttpServletResponse response) {
    // BAD: inline scripts allowed with no nonce or hash.
    response.addHeader("content-security-policy", "script-src 'self' 'unsafe-inline'"); // $ Alert
  }

  public void badScriptSrcEvalWithNonce(HttpServletResponse response) {
    // BAD: a nonce does not neutralize 'unsafe-eval'.
    response.addHeader(
        "Content-Security-Policy", "script-src 'nonce-r4nd0m' 'unsafe-inline' 'unsafe-eval'"); // $ Alert
  }

  public void badViaLocalVariable(HttpServletResponse response) {
    String policy = "default-src 'self' 'unsafe-inline'";
    // BAD: inline scripts allowed through default-src.
    response.setHeader("Content-Security-Policy", policy); // $ Alert
  }

  public void goodStrictPolicy(HttpServletResponse response) {
    // GOOD: no unsafe script sources.
    response.setHeader("Content-Security-Policy", SAFE_POLICY);
  }

  public void goodInlineStylesOnly(HttpServletResponse response) {
    // GOOD: 'unsafe-inline' only applies to styles; script-src overrides default-src.
    response.setHeader(
        "Content-Security-Policy",
        "default-src 'unsafe-inline' 'self'; script-src 'self'; style-src 'unsafe-inline'");
  }

  public void goodInlineWithNonce(HttpServletResponse response) {
    // GOOD: browsers ignore 'unsafe-inline' when a nonce or hash is present.
    response.setHeader(
        "Content-Security-Policy", "script-src 'nonce-r4nd0m' 'unsafe-inline' 'strict-dynamic'");
    response.setHeader(
        "Content-Security-Policy", "script-src 'sha256-abc123=' 'unsafe-inline'");
  }

  public void goodFirstDirectiveWins(HttpServletResponse response) {
    // GOOD: browsers ignore the second, duplicate script-src directive.
    response.setHeader(
        "Content-Security-Policy", "script-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'");
  }

  public void badFirstDirectiveWins(HttpServletResponse response) {
    // BAD: the first script-src directive is the one that applies.
    response.setHeader(
        "Content-Security-Policy", "script-src 'unsafe-inline'; script-src 'self'"); // $ Alert
  }

  public void goodUnrelatedHeaderApi(MailMessage message) {
    // GOOD: not an HTTP response.
    message.setHeader("Content-Security-Policy", "script-src 'unsafe-inline'");
  }

  public void goodReportOnly(HttpServletResponse response) {
    // GOOD: report-only policies are not enforced and are typically used while tightening a policy.
    response.setHeader(
        "Content-Security-Policy-Report-Only", "default-src 'unsafe-inline' 'unsafe-eval'");
  }
}

class MailMessage {
  void setHeader(String name, String value) {}
}
