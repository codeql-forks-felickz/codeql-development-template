import java.io.IOException;
import java.util.Random;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StringPlusServlet extends HttpServlet {
  private static final int MAX_LENGTH = 1000000;

  // BAD: repeated immutable string concatenation takes quadratic time in the user-controlled
  // length; the upper bound of one million is far too large to prevent that.
  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    int length = Integer.parseInt(req.getParameter("length")); // $ Source
    String[] characters = req.getParameterValues("characters");
    Random rand = new Random();
    String s = "";
    for (int i = 0; i < length && i < MAX_LENGTH; i++) { // $ Alert
      s = s + characters[rand.nextInt(characters.length)];
    }
    res.toString();
  }

  // BAD: `+=` on a String in a `while` loop.
  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    int count = Integer.parseInt(req.getParameter("count")); // $ Source
    String s = "";
    int i = 0;
    while (i < count) { // $ Alert
      s += "x";
      i++;
    }
    int n = Integer.parseInt(req.getParameter("n")); // $ Source
    for (int j = 0; j < n || j < 10; j++) { // $ Alert
      s += "x";
    }
    res.toString();
  }
}
