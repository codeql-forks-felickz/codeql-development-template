import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class VulnerableTaskHolder implements Serializable {
  private String taskName;
  private String taskAction;
  private transient String transientAction = "ping localhost";
  private static String staticAction = "ping localhost";

  public VulnerableTaskHolder(String taskName, String taskAction) {
    this.taskName = taskName;
    this.taskAction = taskAction;
  }

  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    if (taskAction.startsWith("sleep") || taskAction.startsWith("ping")) {
      Runtime.getRuntime().exec(taskAction); // $ Alert
    }
    Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "echo " + this.taskName}); // $ Alert
    // Not restored from the stream: transient and static fields.
    Runtime.getRuntime().exec(transientAction);
    Runtime.getRuntime().exec(staticAction);
  }

  // Not a deserialization method.
  public void run() throws IOException {
    Runtime.getRuntime().exec(taskAction);
  }
}

class NotSerializable {
  private String action;

  // Not a deserialization method: the class is not Serializable.
  private void readObject(ObjectInputStream stream) throws IOException {
    Runtime.getRuntime().exec(action);
  }
}
