package org.springframework.security.config.annotation.web;

import org.springframework.http.HttpMethod;

public abstract class AbstractRequestMatcherRegistry<C> {
  public C anyRequest() {
    return null;
  }

  public C requestMatchers(String... patterns) {
    return null;
  }

  public C requestMatchers(HttpMethod method, String... patterns) {
    return null;
  }

  public C antMatchers(HttpMethod method, String... patterns) {
    return null;
  }
}
