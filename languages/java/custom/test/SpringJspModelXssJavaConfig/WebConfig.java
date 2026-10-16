import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;

// JSP views are configured through Spring's Java configuration.
public class WebConfig {
  public void configureViewResolvers(ViewResolverRegistry registry) {
    registry.jsp("/WEB-INF/views/", ".jsp");
  }
}
