import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class Test {

  public interface Command {
    void execute(String arg);
  }

  private static final Set<String> ALLOWED = Set.of("Listen", "Ignore");

  private static final Map<String, Class<? extends Command>> COMMANDS = Map.of();

  private static String ucfirst(String subject) {
    return Character.toUpperCase(subject.charAt(0)) + subject.substring(1);
  }

  // BAD: request parameter mapped to a class name and instantiated (command-to-class mapping).
  public void commandToClass(HttpServletRequest request, String user) throws Exception {
    String command = request.getParameter("command"); // $ Source
    Class<?> cmdClass = Class.forName("com.example.commands." + ucfirst(command) + "Command");
    Command cmd =
        (Command) cmdClass.getDeclaredConstructor(String.class).newInstance(user); // $ Alert
    cmd.execute(user);
  }

  // BAD: legacy Class.newInstance on a user-selected class.
  public Object legacyNewInstance(HttpServletRequest request) throws Exception {
    String name = request.getParameter("class"); // $ Source
    return Class.forName(name).newInstance(); // $ Alert
  }

  // BAD: ClassLoader.loadClass with a user-selected class.
  public Object loadClass(HttpServletRequest request) throws Exception {
    String name = request.getParameter("class"); // $ Source
    Class<?> c = getClass().getClassLoader().loadClass(name);
    return c.getConstructor().newInstance(); // $ Alert
  }

  // BAD: user-selected class and method invoked reflectively.
  public Object invoke(HttpServletRequest request) throws Exception {
    String name = request.getParameter("handler"); // $ Source
    return Class.forName(name).getMethod("handle").invoke(null); // $ Alert
  }

  // GOOD: class name constrained by an allowlist.
  public void allowlisted(HttpServletRequest request, String user) throws Exception {
    String command = request.getParameter("command");
    if (ALLOWED.contains(command)) {
      Class<?> cmdClass = Class.forName("com.example.commands." + command + "Command");
      ((Command) cmdClass.getDeclaredConstructor().newInstance()).execute(user);
    }
  }

  // GOOD: class name compared against a fixed value.
  public void equalsCheck(HttpServletRequest request) throws Exception {
    String command = request.getParameter("command");
    if ("Listen".equals(command)) {
      Class.forName("com.example.commands." + command + "Command").getConstructor().newInstance();
    }
  }

  // GOOD: class selected via a fixed lookup table keyed by the request parameter.
  public void lookupTable(HttpServletRequest request) throws Exception {
    Class<? extends Command> c = COMMANDS.get(request.getParameter("command"));
    if (c != null) {
      c.getConstructor().newInstance().execute("x");
    }
  }

  // GOOD: constant class name.
  public Object constant() throws Exception {
    return Class.forName("com.example.commands.ListenCommand").getConstructor().newInstance();
  }

  // GOOD: user-controlled class is resolved but never instantiated or invoked.
  public boolean onlyResolved(HttpServletRequest request) {
    try {
      Class.forName(request.getParameter("class"));
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }
}
