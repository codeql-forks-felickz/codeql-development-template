package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;

public final class AuthorizeHttpRequestsConfigurer<H> {
  public final class AuthorizationManagerRequestMatcherRegistry
      extends AbstractRequestMatcherRegistry<AuthorizedUrl> {}

  public class AuthorizedUrl {
    public AuthorizationManagerRequestMatcherRegistry permitAll() {
      return null;
    }

    public AuthorizationManagerRequestMatcherRegistry authenticated() {
      return null;
    }

    public AuthorizationManagerRequestMatcherRegistry hasRole(String role) {
      return null;
    }
  }
}
