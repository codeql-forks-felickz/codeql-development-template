package test;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Reduced from the `/infiniteloop` handler of a synthetic vulnerable application.
@WebServlet(urlPatterns = {"/infiniteloop"})
public class InfiniteLoopServlet extends HttpServlet {
  private static final boolean RUNNING = true;

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    while (true) { // $ Alert
      String contextPath = req.getContextPath();
      int contentLength = req.getContentLength();
      System.out.println(contextPath + contentLength);
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    if (req.getContentLength() > 0) {
      spin(req);
    }
    for (;;) { // $ Alert
      // A `return` inside a lambda does not leave the loop.
      Runnable r = () -> {
        return;
      };
      r.run();
    }
  }

  @Override
  public void service(javax.servlet.ServletRequest req, javax.servlet.ServletResponse res) {
    do {
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        // swallowed, so the loop keeps going
      }
    } while (RUNNING); // $ Alert
  }

  // Not a handler itself, but reachable from `doPost`.
  private void spin(HttpServletRequest req) {
    int n = 0;
    while (1 == 1) { // $ Alert
      n += req.getContentLength();
      inner:
      while (true) {
        // Breaks only out of the inner loop.
        break inner;
      }
    }
  }
}
