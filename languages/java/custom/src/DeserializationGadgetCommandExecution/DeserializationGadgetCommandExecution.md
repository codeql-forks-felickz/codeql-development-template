# Command execution from a deserialization callback

Java serialization calls `readObject`, `readObjectNoData`, `readResolve` and
`Externalizable.readExternal` while it rebuilds an object, before application code can check
the result. The fields of the object, and anything read from the stream, come straight from the
serialized bytes. If one of these callbacks builds a command line from that state and passes it to
`Runtime.exec` or `ProcessBuilder`, the class is a ready-made gadget. Any endpoint that
deserializes untrusted data (for example with `ObjectInputStream.readObject`) then lets an attacker
run arbitrary commands.

The query treats as untrusted:

- reads of non-static, non-transient fields of the object being deserialized inside these callbacks
- values read from the callback's `ObjectInputStream` or `ObjectInput` parameter

It reports when that data reaches a command-injection sink. Prefix checks such as
`startsWith("ping")` or length limits are not treated as validation.

## Recommendation

Do not perform side effects such as running commands in deserialization callbacks. Validate
restored state against a fixed set of allowed values, or move the action to an explicit method
that runs after the object has been checked. Avoid deserializing untrusted data altogether, or
restrict the accepted classes with an `ObjectInputFilter`.

## Example

The following class runs a deserialized field as a command:

```java
private void readObject(ObjectInputStream stream) throws Exception {
  stream.defaultReadObject();
  if (taskAction.startsWith("ping") && taskAction.length() < 22) {
    Runtime.getRuntime().exec(taskAction);
  }
}
```

Instead, only select from fixed commands:

```java
private void readObject(ObjectInputStream stream) throws Exception {
  stream.defaultReadObject();
  if ("cleanup".equals(taskAction)) {
    Runtime.getRuntime().exec(new String[] {"/usr/bin/cleanup"});
  }
}
```

## References

- OWASP: [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Common Weakness Enumeration: [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
