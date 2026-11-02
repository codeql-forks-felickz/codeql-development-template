import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// BAD: the second lock is acquired in a helper method called while the first lock is held,
// and the locks are static, so they are shared by every instance.
@WebServlet("/transfer")
public class IndirectDeadlockServlet extends HttpServlet {
  private static final Object ACCOUNTS = new Object();
  private static final Object AUDIT = new Object();

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res) {
    synchronized (ACCOUNTS) { // $ Alert
      audit();
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res) {
    synchronized (AUDIT) { // $ Alert
      updateAccounts();
    }
  }

  private void audit() {
    synchronized (AUDIT) {
    }
  }

  private void updateAccounts() {
    synchronized (ACCOUNTS) {
    }
  }
}
