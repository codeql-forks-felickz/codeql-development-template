import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

public class ServletDeserialization extends HttpServlet {

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    // BAD: base64 request parameter decoded with java.util.Base64.
    byte[] raw = Base64.getDecoder().decode(request.getParameter("data"));
    new ObjectInputStream(new ByteArrayInputStream(raw)).readObject();

    // BAD: base64 "view state" decoded with javax.xml.bind.DatatypeConverter.
    String state = request.getParameter("state");
    byte[] data = DatatypeConverter.parseBase64Binary(state.trim());
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();
    ois.close();

    // BAD: raw request body copied into a buffer and deserialized.
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    InputStream in = request.getInputStream();
    byte[] chunk = new byte[4096];
    int n;
    while ((n = in.read(chunk)) != -1) {
      buf.write(chunk, 0, n);
    }
    byte[] body = buf.toByteArray();
    ObjectInputStream bodyStream = new ObjectInputStream(new ByteArrayInputStream(body));
    bodyStream.readObject();
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    // GOOD: the serialized data is a server-side constant, not user-controlled.
    byte[] trusted = Base64.getDecoder().decode("rO0ABXQABWhlbGxv");
    new ObjectInputStream(new ByteArrayInputStream(trusted)).readObject();
  }
}
