import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.math.NumberUtils;

public class CreatingObjectsServlet extends HttpServlet {
  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    int number = NumberUtils.toInt(req.getParameter("number"), -1); // $ Source
    if (number >= 1) {
      calcSum1(number);
    }
  }

  // BAD: one boxed `Long` is allocated per iteration, and the number of iterations is
  // user-controlled.
  private Long calcSum1(int number) {
    Long sum = 0L;
    for (long i = 1; i <= number; i++) { // $ Alert
      sum += i;
    }
    return sum;
  }
}
