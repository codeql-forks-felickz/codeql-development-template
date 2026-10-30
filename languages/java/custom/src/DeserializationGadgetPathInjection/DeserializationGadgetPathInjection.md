# Deserialization callback uses deserialized state as a file path

A class that implements `java.io.Serializable` can define `readObject`, `readExternal` or
`readResolve`. The serialization runtime calls these methods while it reconstructs an object, and
the object's non-transient fields contain whatever the serialized stream supplied. If one of these
callbacks uses that state to build a file path (for example `new FileWriter(filename)`), the class
becomes a deserialization gadget: anyone who can get the application to deserialize a stream they
control can read, create or overwrite arbitrary files.

This query reports file-path sinks reached from deserialized fields or stream reads inside these
callbacks. It does not require a reachable `ObjectInputStream.readObject` call on untrusted data,
so it reports the gadget even when the deserialization entry point is elsewhere (or in another
application on the same classpath).

## Recommendation

Do not perform file-system side effects in deserialization callbacks. If a callback must touch
the file system, validate the path against a fixed allow list or base directory, or mark the
field `transient` and recompute it from trusted data. Also restrict which classes may be
deserialized with an `ObjectInputFilter`.

## Example

```java
class LogFile implements Serializable {
  public String filename;
  public String filecontent;

  private void readObject(ObjectInputStream in) throws Exception {
    in.defaultReadObject();
    try (FileWriter out = new FileWriter(filename)) { // BAD: path from the stream
      out.write(filecontent);
    }
  }
}
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP: Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
