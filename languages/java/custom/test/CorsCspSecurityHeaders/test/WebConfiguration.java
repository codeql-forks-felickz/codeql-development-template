package test;

import java.util.Arrays;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// Reduced from a Spring MVC configuration with a permissive CORS mapping (CWE-942).
public class WebConfiguration implements WebMvcConfigurer {
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    // BAD: allowed origins left at the permissive default ("*").
    registry.addMapping("/**").allowedMethods("*"); // $ Alert
  }

  public void badExplicitWildcard(CorsRegistry registry) {
    // BAD: every origin allowed explicitly.
    registry.addMapping("/api/**").allowedOrigins("*").allowedMethods("GET"); // $ Alert
  }

  public void badWildcardPatternWithCredentials(CorsRegistry registry) {
    // BAD: any origin may send credentialed requests.
    registry
        .addMapping("/api/**") // $ Alert
        .allowedOriginPatterns("*")
        .allowCredentials(true);
  }

  public void goodSpecificOrigin(CorsRegistry registry) {
    // GOOD: origins restricted.
    registry.addMapping("/**").allowedOrigins("https://app.example.com").allowedMethods("*");
  }

  public void goodSpecificOriginViaVariable(CorsRegistry registry) {
    // GOOD: origins restricted on the stored registration.
    CorsRegistration registration = registry.addMapping("/api/**");
    registration.allowedMethods("GET");
    registration.allowedOriginPatterns("https://*.example.com");
  }

  public void goodConfiguredOrigins(CorsRegistry registry, String[] trustedOrigins) {
    // GOOD: origins come from configuration.
    registry.addMapping("/**").allowedOrigins(trustedOrigins);
  }

  public void goodConfiguredByHelper(CorsRegistry registry) {
    // GOOD: the registration is configured elsewhere.
    configureOrigins(registry.addMapping("/api/**"));
  }

  private void configureOrigins(CorsRegistration registration) {
    registration.allowedOrigins("https://app.example.com");
  }

  public CorsConfiguration listConfiguration() {
    CorsConfiguration config = new CorsConfiguration();
    // BAD: every origin allowed.
    config.setAllowedOrigins(Arrays.asList("*")); // $ Alert
    // GOOD: specific origin pattern.
    config.setAllowedOriginPatterns(Arrays.asList("https://*.example.com"));
    return config;
  }

  public CorsConfiguration corsConfiguration() {
    CorsConfiguration config = new CorsConfiguration();
    // BAD: every origin allowed.
    config.addAllowedOrigin("*"); // $ Alert
    // GOOD: a specific origin.
    config.addAllowedOrigin("https://app.example.com");
    config.addAllowedMethod("*");
    return config;
  }
}
