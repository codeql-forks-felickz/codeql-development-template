import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// BAD: the servlet instance (and its lock fields) is shared by all concurrent requests, and
// consecutive requests acquire `lock1` and `lock2` in opposite orders.
@WebServlet(urlPatterns = {"/deadlock"})
public class DeadlockServlet extends HttpServlet {
  private final Object lock1 = new Object();
  private final Object lock2 = new Object();
  private boolean switchFlag = true;

  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res) {
    switchFlag = !switchFlag;
    if (switchFlag) {
      lock12();
    } else {
      lock21();
    }
  }

  private void lock12() {
    synchronized (lock1) { // $ Alert
      synchronized (lock2) {
        work();
      }
    }
  }

  private void lock21() {
    synchronized (lock2) { // $ Alert
      synchronized (lock1) {
        work();
      }
    }
  }

  private void work() {}
}
