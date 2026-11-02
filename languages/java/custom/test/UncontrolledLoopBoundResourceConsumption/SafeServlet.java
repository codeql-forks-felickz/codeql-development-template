import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
  private static final int MAX_COUNT = 1000;

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    int n = Integer.parseInt(req.getParameter("n"));
    stringBuilder(n);
    primitiveSum(n);
    guarded(n);
    smallLoopBound(n);
    constantBound();
  }

  // GOOD: StringBuilder appends in amortized constant time.
  private String stringBuilder(int n) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      sb.append('x');
    }
    return sb.toString();
  }

  // GOOD: primitive arithmetic does not allocate.
  private long primitiveSum(int n) {
    long sum = 0L;
    for (long i = 1; i <= n; i++) {
      sum += i;
    }
    return sum;
  }

  // GOOD: the user-controlled value is checked against a small limit first.
  private String guarded(int n) {
    if (n > MAX_COUNT) {
      return "";
    }
    String s = "";
    for (int i = 0; i < n; i++) {
      s += "x";
    }
    return s;
  }

  // GOOD: the loop condition also has a small constant bound.
  private Long smallLoopBound(int n) {
    Long sum = 0L;
    for (int i = 0; i < n && i < 100; i++) {
      sum += i;
    }
    return sum;
  }

  // GOOD: the bound is not user-controlled.
  private String constantBound() {
    String s = "";
    for (int i = 0; i < 1000000; i++) {
      s += "x";
    }
    return s;
  }
}
