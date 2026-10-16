import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

public class JacksonCookieDeserialization {

  // A mapper that lets the JSON choose any class on the classpath.
  private static final ObjectMapper POLYMORPHIC_MAPPER = createPolymorphicMapper();

  // A mapper bound to a fixed type, without default typing.
  private static final ObjectMapper TYPED_MAPPER = new ObjectMapper();

  // A mapper with default typing restricted by an allowlisting validator.
  private static final ObjectMapper ALLOWLIST_MAPPER = createAllowlistMapper();

  private static ObjectMapper createPolymorphicMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.activateDefaultTyping(
        LaissezFaireSubTypeValidator.instance,
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY);
    return mapper;
  }

  private static ObjectMapper createAllowlistMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder().allowIfSubType("com.example.model.").build(),
        ObjectMapper.DefaultTyping.NON_FINAL);
    return mapper;
  }

  private static byte[] decode(String base64Payload) {
    return Base64.getDecoder().decode(base64Payload);
  }

  public static Object deserializePolymorphicUnsafe(String base64Payload) throws Exception {
    // BAD (called with a cookie value): default typing with a laissez-faire validator.
    return POLYMORPHIC_MAPPER.readValue(decode(base64Payload), Object.class);
  }

  public static Object deserializeTyped(String base64Payload) throws Exception {
    // GOOD: no default typing, bound to a fixed class.
    return TYPED_MAPPER.readValue(decode(base64Payload), String.class);
  }

  public static Object deserializeAllowlisted(String base64Payload) throws Exception {
    // GOOD: default typing restricted by an allowlisting validator.
    return ALLOWLIST_MAPPER.readValue(decode(base64Payload), Object.class);
  }

  @RestController
  public static class Controller {
    @RequestMapping("/level4")
    public Object level4(@CookieValue(value = "activity", required = false) String cookie)
        throws Exception {
      return deserializePolymorphicUnsafe(cookie);
    }

    @RequestMapping("/typed")
    public Object typed(@CookieValue(value = "prefs", required = false) String cookie)
        throws Exception {
      return deserializeTyped(cookie);
    }

    @RequestMapping("/allowlisted")
    public Object allowlisted(@CookieValue(value = "prefs", required = false) String cookie)
        throws Exception {
      return deserializeAllowlisted(cookie);
    }
  }

  public static class CookieServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws Exception {
      for (Cookie cookie : request.getCookies()) {
        // BAD: legacy enableDefaultTyping, cookie value Base64-decoded.
        ObjectMapper m = new ObjectMapper();
        m.enableDefaultTyping();
        m.readValue(Base64.getDecoder().decode(cookie.getValue()), Object.class);

        // BAD: activateDefaultTyping with a laissez-faire validator in the same method.
        ObjectMapper m2 = new ObjectMapper();
        m2.activateDefaultTyping(
            new LaissezFaireSubTypeValidator(), ObjectMapper.DefaultTyping.EVERYTHING);
        m2.readValue(Base64.getDecoder().decode(cookie.getValue()), Object.class);

        // BAD: activateDefaultTypingAsProperty with a laissez-faire validator.
        ObjectMapper m3 = new ObjectMapper();
        m3.activateDefaultTypingAsProperty(
            LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL, "@type");
        m3.readValue(cookie.getValue(), Object.class);

        // BAD: laissez-faire validator passed through a local variable.
        PolymorphicTypeValidator ptv = LaissezFaireSubTypeValidator.instance;
        ObjectMapper m4 = new ObjectMapper();
        m4.activateDefaultTyping(ptv);
        m4.readValue(cookie.getValue(), Object.class);
      }
    }
  }
}
