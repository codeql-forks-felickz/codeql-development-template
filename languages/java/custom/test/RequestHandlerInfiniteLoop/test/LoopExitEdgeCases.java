package test;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoopExitEdgeCases extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    caughtResourceInitializer();
    uncaughtResourceInitializer();
    unreachableReturn();
    reachableReturn();
    updateException(res);
    initializerException(res);
  }

  private void caughtResourceInitializer() {
    while (true) { // $ Alert
      try (java.io.InputStream in = new java.io.FileInputStream("test")) {
      } catch (IOException e) {
      }
    }
  }

  private void uncaughtResourceInitializer() throws IOException {
    while (true) {
      try (java.io.InputStream in = new java.io.FileInputStream("test")) {
      }
    }
  }

  private void unreachableReturn() {
    while (true) { // $ Alert
      if (false) {
        return;
      }
    }
  }

  private void reachableReturn() {
    while (true) {
      if (true) {
        return;
      }
    }
  }

  private void updateException(HttpServletResponse res) throws IOException {
    for (;; res.flushBuffer()) {
    }
  }

  private void initializerException(HttpServletResponse res) throws IOException {
    for (res.flushBuffer();; ) { // $ Alert
    }
  }
}
