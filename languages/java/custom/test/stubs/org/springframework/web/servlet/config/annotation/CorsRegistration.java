package org.springframework.web.servlet.config.annotation;

public class CorsRegistration {
  public CorsRegistration allowedOrigins(String... origins) {
    return this;
  }

  public CorsRegistration allowedOriginPatterns(String... patterns) {
    return this;
  }

  public CorsRegistration allowedMethods(String... methods) {
    return this;
  }

  public CorsRegistration allowedHeaders(String... headers) {
    return this;
  }

  public CorsRegistration allowCredentials(boolean allowCredentials) {
    return this;
  }
}
