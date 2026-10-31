import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Date;
import java.util.UUID;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A mapper with default typing that only reads back JSON it has just written itself from a
 * server-built object whose fields are plain scalar types. User input only ends up in string
 * values, which Jackson escapes, so it cannot inject a type id.
 */
public class JacksonRoundTrip {

  public static class Post {
    private final String postId;
    private final String body;
    private final Date timestamp;

    public Post(String postId, String body, Date timestamp) {
      this.postId = postId;
      this.body = body;
      this.timestamp = timestamp;
    }

    public String getPostId() {
      return postId;
    }

    public String getBody() {
      return body;
    }

    public Date getTimestamp() {
      return timestamp;
    }
  }

  public static class SerializedPost extends Post {
    private final UUID serialId;

    public SerializedPost(String postId, String body, Date timestamp, UUID serialId) {
      super(postId, body, timestamp);
      this.serialId = serialId;
    }

    public UUID getSerialId() {
      return serialId;
    }
  }

  public static class PostSerializer {
    public boolean serializePost(final SerializedPost serializedPost) {
      ObjectMapper mapper = new ObjectMapper();
      mapper.enableDefaultTyping();
      try {
        String written = mapper.writeValueAsString(serializedPost);
        // GOOD: round trip of server-generated JSON; the user cannot choose the type.
        return mapper.readValue(written, SerializedPost.class) != null;
      } catch (Exception e) {
        return false;
      }
    }

    public Object readClientJson(String json) throws Exception {
      ObjectMapper mapper = new ObjectMapper();
      mapper.enableDefaultTyping();
      // BAD: the client-supplied JSON is read directly, so it can name the class to create.
      return mapper.readValue(json, Object.class);
    }
  }

  @RestController
  public static class Controller {
    private final PostSerializer postSerializer = new PostSerializer();

    @RequestMapping("/post/{postid}")
    public Post getPost(@PathVariable("postid") String postId, @CookieValue("body") String body) {
      postSerializer.serializePost(new SerializedPost(postId, body, new Date(), UUID.randomUUID()));
      return new Post(postId, body, new Date());
    }

    @RequestMapping("/import")
    public Object importPost(@CookieValue("json") String json) throws Exception {
      return postSerializer.readClientJson(json);
    }
  }
}
