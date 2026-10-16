import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.Serializable;

// BAD: deserialized field executed as a command from `readObject` (gadget).
class TaskHolder implements Serializable {
  private static final long serialVersionUID = 1L;

  private String taskName;
  private String taskAction;

  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    if ((taskAction.startsWith("sleep") || taskAction.startsWith("ping"))
        && taskAction.length() < 22) {
      Runtime.getRuntime().exec(taskAction); // $ Alert
    }
  }
}

// BAD: value read directly from the stream and passed to ProcessBuilder.
class StreamCommand implements Serializable {
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    String cmd = in.readUTF(); // $ Source
    new ProcessBuilder("sh", "-c", cmd).start(); // $ Alert
  }
}

// BAD: deserialized field executed from a helper called by `readResolve`.
class ResolveCommand implements Serializable {
  private String command;

  private Object readResolve() throws IOException {
    run(this.command); // $ Source
    return this;
  }

  private static void run(String c) throws IOException {
    Runtime.getRuntime().exec(c); // $ Alert
  }
}

// BAD: `Externalizable.readExternal` gadget.
class ExternalCommand implements Externalizable {
  private String command;

  public void writeExternal(ObjectOutput out) throws IOException {}

  public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    command = (String) in.readObject();
    Runtime.getRuntime().exec(command); // $ Alert
  }
}

// GOOD: deserialized field only selects from fixed commands.
class SafeTaskHolder implements Serializable {
  private String taskAction;

  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    if ("cleanup".equals(taskAction)) {
      Runtime.getRuntime().exec(new String[] {"/usr/bin/cleanup"});
    }
  }
}

// GOOD: transient field is not populated by deserialization.
class TransientHolder implements Serializable {
  private transient String command = "/usr/bin/true";

  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    Runtime.getRuntime().exec(command);
  }
}

// GOOD: field executed outside of deserialization callbacks.
class NotAGadget implements Serializable {
  private String command;

  public void runLater() throws IOException {
    Runtime.getRuntime().exec(command);
  }
}
