# H2 database console exposed to remote hosts

The H2 web console is a database administration tool. Spring Boot can serve it from the application when `spring.h2.console.enabled=true`. By default it only accepts connections from the local host, but `spring.h2.console.settings.web-allow-others=true` makes it reachable from any host. If this is set in `application.properties` or in a profile that `spring.profiles.active` activates, the deployed application exposes a database console that can be used to read or modify data, and in some H2 versions to run code.

The query only reports settings that are loaded by default: the base `application.properties` file, or an `application-<profile>.properties` file whose profile is listed in `spring.profiles.active`. Development-only profiles that are not activated by default are not reported.

## Recommendation

Do not enable the H2 console in production configuration. If it is needed during development, enable it only in a profile that is not active by default, and keep `web-allow-others` set to `false`.

## Example

```properties
# application.properties
spring.profiles.active=unsafe

# application-unsafe.properties
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true   # BAD
```

## References

- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [Spring Boot: H2 Console](https://docs.spring.io/spring-boot/reference/data/sql.html#data.sql.h2-web-console)
