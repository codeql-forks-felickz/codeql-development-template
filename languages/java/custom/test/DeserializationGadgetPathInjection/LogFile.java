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

// Gadget: an alias of the callback stream still reads attacker-controlled data.
class AliasedStreamPath implements Serializable {
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream stream = in;
    String path = stream.readUTF(); // $ Source
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

// Gadget: readResolve has a non-void reference return type.
class ReadResolveFile implements Serializable {
  public String filename;

  private Object readResolve() throws Exception {
    new FileWriter(filename).close(); // $ Alert
    return this;
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

// Safe: the restored path field is overwritten before it is read.
class OverwrittenPathLog implements Serializable {
  public String filename;

  private void readObject(ObjectInputStream in) throws Exception {
    in.defaultReadObject();
    filename = "/var/log/app.log";
    new FileWriter(filename).close();
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

// Safe: a public readObject method is not a serialization callback.
class PublicReadObject implements Serializable {
  public String filename;

  public void readObject(ObjectInputStream in) throws Exception {
    new FileWriter(filename).close();
  }
}

// Safe: readExternal is only a callback for Externalizable classes.
class SerializableReadExternal implements Serializable {
  public String filename;

  public void readExternal(ObjectInput in) throws Exception {
    new FileWriter(filename).close();
  }
}

// Safe: readResolve cannot return void.
class VoidReadResolve implements Serializable {
  public String filename;

  private void readResolve() throws Exception {
    new FileWriter(filename).close();
  }
}

// Safe: readObject cannot be static.
class StaticReadObject implements Serializable {
  private static void readObject(ObjectInputStream in) throws Exception {
    String path = in.readUTF();
    new File(path).delete();
  }
}

// Safe: this similarly named method is not called on the callback stream.
class UnrelatedInput {
  String readUTF() {
    return "/var/log/app.log";
  }
}

class UnrelatedStreamPath implements Serializable {
  private void readObject(ObjectInputStream in) throws Exception {
    String path = new UnrelatedInput().readUTF();
    new File(path).delete();
  }
}

// Safe: not Serializable, so readObject is never a deserialization callback.
class NotSerializable {
  public String filename;

  private void readObject(ObjectInputStream in) throws Exception {
    new FileWriter(filename).close();
  }
}
