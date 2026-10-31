package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class HeadersConfigurer {
  public FrameOptionsConfig frameOptions() {
    return null;
  }

  public HeadersConfigurer frameOptions(Customizer<FrameOptionsConfig> frameOptionsCustomizer) {
    return this;
  }

  public ContentSecurityPolicyConfig contentSecurityPolicy(String policyDirectives) {
    return null;
  }

  public HttpSecurity disable() {
    return null;
  }

  public class FrameOptionsConfig {
    public HeadersConfigurer deny() {
      return null;
    }

    public HeadersConfigurer sameOrigin() {
      return null;
    }

    public HeadersConfigurer disable() {
      return null;
    }
  }

  public class ContentSecurityPolicyConfig {
    public ContentSecurityPolicyConfig policyDirectives(String policyDirectives) {
      return this;
    }
  }
}
