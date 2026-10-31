import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// GOOD: the locks are always acquired in the same order.
@WebServlet("/ordered")
class ConsistentOrderServlet extends HttpServlet {
  private final Object lock1 = new Object();
  private final Object lock2 = new Object();
  private boolean switchFlag = true;

  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res) {
    switchFlag = !switchFlag;
    if (switchFlag) {
      a();
    } else {
      b();
    }
  }

  private void a() {
    synchronized (lock1) {
      synchronized (lock2) {
      }
    }
  }

  private void b() {
    synchronized (lock1) {
      synchronized (lock2) {
      }
    }
  }
}

// GOOD: the locks are local to each request, so concurrent requests never share them.
@WebServlet("/local")
class LocalLockServlet extends HttpServlet {
  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res) {
    Object lock1 = new Object();
    Object lock2 = new Object();
    synchronized (lock1) {
      synchronized (lock2) {
      }
    }
    synchronized (lock2) {
      synchronized (lock1) {
      }
    }
  }
}

// GOOD: the lock order is only inverted in a sequential, non-overlapping way: the first
// lock is released before the second is acquired.
@WebServlet("/sequential")
class SequentialLockServlet extends HttpServlet {
  private final Object lock1 = new Object();
  private final Object lock2 = new Object();

  @Override
  protected void service(HttpServletRequest req, HttpServletResponse res) {
    synchronized (lock1) {
      synchronized (lock2) {
      }
    }
    synchronized (lock2) {
    }
    synchronized (lock1) {
    }
  }
}

// NOT REPORTED HERE: not a request handler (use `java/lock-order-inconsistency`).
class NotAServlet {
  private final Object lock1 = new Object();
  private final Object lock2 = new Object();

  void a() {
    synchronized (lock1) {
      synchronized (lock2) {
      }
    }
  }

  void b() {
    synchronized (lock2) {
      synchronized (lock1) {
      }
    }
  }
}
