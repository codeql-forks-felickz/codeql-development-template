package org.springframework.security.config.annotation.web.builders;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

public final class HttpSecurity {
  public HttpSecurity authorizeHttpRequests(
      Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
          customizer) {
    return this;
  }
}
