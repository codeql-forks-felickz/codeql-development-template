import java.io.*;

// Reported by the stock java/unsafe-deserialization query only when the `local` (file)
// threat model is enabled, see UnsafeDeserialization.ext.yml.
class Utils {
  public static Object DeserializeFromFile(String filename) {
    Object obj = new Object();
    try {
      FileInputStream file = new FileInputStream(filename); // $ Source
      ObjectInputStream in = new ObjectInputStream(file);
      obj = in.readObject(); // $ Alert
      in.close();
      file.close();
    } catch (Exception e) {
    }
    return obj;
  }
}
