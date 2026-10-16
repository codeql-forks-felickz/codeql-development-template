import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Base64;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller declared through custom annotations that are meta-annotated with Spring's
 * {@code @RestController} and {@code @RequestMapping}, with deserialization helpers in a separate
 * utility class that wraps exceptions.
 */
public class MetaAnnotatedController {

  @Target(ElementType.TYPE)
  @Retention(RetentionPolicy.RUNTIME)
  @RestController
  @RequestMapping
  public @interface AppRestController {
    String value();
  }

  @Target(ElementType.METHOD)
  @Retention(RetentionPolicy.RUNTIME)
  @RequestMapping
  public @interface AppRequestMapping {
    String value();
  }

  public static class Preferences {
    public String role;
  }

  public static class AppException extends Exception {
    public AppException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static class Utils {
    private static final ObjectMapper TYPED_MAPPER = new ObjectMapper();

    private static final ObjectMapper POLYMORPHIC_MAPPER = createPolymorphicMapper();

    private static ObjectMapper createPolymorphicMapper() {
      ObjectMapper mapper = new ObjectMapper();
      mapper.activateDefaultTyping(
          LaissezFaireSubTypeValidator.instance,
          ObjectMapper.DefaultTyping.NON_FINAL,
          JsonTypeInfo.As.PROPERTY);
      return mapper;
    }

    private static byte[] decode(String base64Payload) {
      return Base64.getDecoder().decode(base64Payload);
    }

    public static <T> T deserializeUnsafe(String base64Payload, Class<T> type)
        throws AppException {
      try {
        // GOOD (for this query): no default typing and bound to a fixed class, so the payload
        // cannot select the type to instantiate. Missing integrity protection on the cookie is
        // a data-tampering issue rather than unsafe deserialization of arbitrary types.
        return TYPED_MAPPER.readValue(decode(base64Payload), type);
      } catch (IOException e) {
        throw new AppException("Failed to deserialize payload", e);
      }
    }

    public static Object deserializePolymorphicUnsafe(String base64Payload) throws AppException {
      try {
        // BAD: the cookie selects any class on the classpath.
        return POLYMORPHIC_MAPPER.readValue(decode(base64Payload), Object.class);
      } catch (IOException e) {
        throw new AppException("Failed to deserialize payload", e);
      }
    }
  }

  @AppRestController("InsecureDeserialization")
  public static class Vulnerability {
    @AppRequestMapping("LEVEL_2")
    public String level2(@CookieValue(value = "session", required = false) String sessionCookie) {
      if (sessionCookie == null || sessionCookie.isEmpty()) {
        return "starting";
      }
      try {
        Preferences session = Utils.deserializeUnsafe(sessionCookie, Preferences.class);
        return session.role;
      } catch (AppException e) {
        return e.getMessage();
      }
    }

    @AppRequestMapping("LEVEL_4")
    public String level4(@CookieValue(value = "activity", required = false) String activityCookie) {
      if (activityCookie == null || activityCookie.isEmpty()) {
        return "visit";
      }
      try {
        Object result = Utils.deserializePolymorphicUnsafe(activityCookie);
        return String.valueOf(result);
      } catch (AppException e) {
        return e.getMessage();
      }
    }
  }
}
