package test;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SecurityConfig {
  public void configure(HttpSecurity http) {
    // GOOD: framing restricted to the same origin.
    http.headers().frameOptions().sameOrigin();
  }
}
