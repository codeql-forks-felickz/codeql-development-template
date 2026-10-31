package test;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;

public class WebSecurityConfig {
  public void badFrameOptionsDisabled(HttpSecurity http) {
    // BAD: Spring Security's X-Frame-Options header is turned off.
    http.headers().frameOptions().disable(); // $ Alert
  }

  public void badAllHeadersDisabled(HttpSecurity http) {
    // BAD: all Spring Security response headers, including X-Frame-Options, are turned off.
    http.headers().disable(); // $ Alert
  }

  public void badLambdaDsl(HttpSecurity http) {
    // BAD: lambda DSL variant.
    http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable())); // $ Alert
  }

  public void badMethodReference(HttpSecurity http) {
    // BAD: method-reference variant.
    http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)); // $ Alert
  }

  public void goodSameOrigin(HttpSecurity http) {
    // GOOD: framing restricted to the same origin.
    http.headers().frameOptions().sameOrigin();
  }

  public void badSpringSecurityCsp(HttpSecurity http) {
    // BAD: inline scripts allowed.
    http.headers().contentSecurityPolicy("script-src 'self' 'unsafe-inline'"); // $ Alert
  }

  public void goodSpringSecurityCsp(HttpSecurity http) {
    // GOOD: strict policy.
    http.headers()
        .contentSecurityPolicy("default-src 'self'")
        .policyDirectives("script-src 'self'; frame-ancestors 'none'");
  }
}
