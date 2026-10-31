import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class WebSecurityConfig {
  HttpSecurity filterChain(HttpSecurity http) {
    return http.authorizeHttpRequests(
        auth ->
            auth.requestMatchers("/css/**", "/images/**")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/login", "/register.mvc")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/mail") // $ Alert
                .permitAll()
                .antMatchers(HttpMethod.DELETE, "/api/users/**") // $ Alert
                .permitAll()
                .requestMatchers(HttpMethod.PUT, "/api/profile")
                .authenticated()
                .requestMatchers(HttpMethod.GET, "/public/**")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/oauth2/token", "/password/reset")
                .permitAll()
                .requestMatchers("/service/admin/**")
                .hasRole("ADMIN")
                .anyRequest()
                .authenticated());
  }
}
