package test;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    // Bounded loop.
    for (int i = 0; i < req.getContentLength(); i++) {
      System.out.println(i);
    }
    // `while (true)` with a `break`.
    int n = 0;
    while (true) {
      if (n++ > 10) {
        break;
      }
    }
    // `while (true)` with a `return`.
    while (true) {
      if (req.getContentLength() == n) {
        return;
      }
      n++;
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    // Streaming loop that ends when the client disconnects (checked `IOException`).
    PrintWriter out = res.getWriter();
    while (true) {
      out.println("ping");
      res.flushBuffer();
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  @Override
  public void service(javax.servlet.ServletRequest req, javax.servlet.ServletResponse res) {
    // Explicit `throw` that leaves the loop.
    while (true) {
      if (req.getContentLength() < 0) {
        throw new IllegalStateException();
      }
    }
  }

  // Labeled `break` / `continue` that leave the inner loop.
  protected void doPut(HttpServletRequest req, HttpServletResponse res) {
    outer:
    for (int i = 0; i < 10; i++) {
      while (true) {
        if (req.getContentLength() == i) {
          continue outer;
        }
        break outer;
      }
    }
  }
}
