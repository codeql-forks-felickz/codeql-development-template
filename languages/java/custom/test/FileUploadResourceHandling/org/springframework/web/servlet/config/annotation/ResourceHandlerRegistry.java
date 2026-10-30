package org.springframework.web.servlet.config.annotation;

public class ResourceHandlerRegistry {
  public ResourceHandlerRegistration addResourceHandler(String... pathPatterns) {
    return new ResourceHandlerRegistration();
  }
}
