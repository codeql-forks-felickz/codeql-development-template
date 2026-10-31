package org.springframework.security.config.annotation.web.builders;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;

public class HttpSecurity {
  public HeadersConfigurer headers() {
    return null;
  }

  public HttpSecurity headers(Customizer<HeadersConfigurer> headersCustomizer) {
    return this;
  }
}
