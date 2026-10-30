import java.io.*;

// Gadget: fields restored from the stream choose which file is written.
class LogFile implements Serializable {
  public String filename;
  public String filecontent;

  private void readObject(ObjectInputStream in) {
    try {
      in.defaultReadObject();
      FileWriter file = new FileWriter(filename); // $ Alert
      BufferedWriter out = new BufferedWriter(file);
      out.write(filecontent);
      out.close();
      file.close();
    } catch (Exception e) {
    }
  }
}

// Gadget: path read explicitly from the stream.
class StreamPathCache implements Serializable {
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    String path = in.readUTF(); // $ Source
    new File(path).delete(); // $ Alert
  }
}

// Gadget: Externalizable callback.
class ExternalLog implements Externalizable {
  public ExternalLog() {}

  public void writeExternal(ObjectOutput out) throws IOException {}

  public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
    String path = (String) in.readObject(); // $ Source
    new FileInputStream(path).close(); // $ Alert
  }
}

// Safe: the path field is transient, so it is not restored from the stream.
class TransientPathLog implements Serializable {
  private transient String filename = "/var/log/app.log";
  public String filecontent;

  private void readObject(ObjectInputStream in) throws Exception {
    in.defaultReadObject();
    try (FileWriter out = new FileWriter(filename)) {
      out.write(filecontent);
    }
  }
}

// Safe: constant path.
class FixedPathLog implements Serializable {
  public String filecontent;

  private void readObject(ObjectInputStream in) throws Exception {
    in.defaultReadObject();
    try (FileWriter out = new FileWriter("/var/log/app.log")) {
      out.write(filecontent);
    }
  }
}

// Safe: not Serializable, so readObject is never a deserialization callback.
class NotSerializable {
  public String filename;

  private void readObject(ObjectInputStream in) throws Exception {
    new FileWriter(filename).close();
  }
}
