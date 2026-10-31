# Uncontrolled command line (extended)

This query is a variant of the standard `java/command-line-injection` query. It reuses the standard sources, sinks, barriers and taint steps, and adds the following models:

- **Deserialized fields**: reads of non-static, non-transient fields of the current object inside a custom `readObject(ObjectInputStream)` method of a `Serializable` class are treated as untrusted. Their values come from the serialized stream, so a class that runs a command from such a field is a ready-made deserialization gadget.
- **Kotlin `Editable.toString()`**: in Kotlin, `editText.text.toString()` is bound to `Object.toString` through an implicit cast, so the standard taint step for Android `Editable` text (which applies to Java code) does not apply. This query adds the step for Kotlin.

Results that `java/command-line-injection` already reports are not repeated.

Command lines built inside JSP files are not covered, because JSP files are not extracted. Precompile JSP files to Java (for example with `jspc`) in a traced build to analyze them.

## Recommendation

Do not build command lines from untrusted data. Pass a fixed command and validate each argument against an allow list. Do not run commands from fields of deserialized objects.

## Example

```java
public class TaskHolder implements Serializable {
  private String taskAction;

  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    // BAD: the command comes from the deserialized stream
    Runtime.getRuntime().exec(taskAction);
  }
}
```

```kotlin
runButton.setOnClickListener {
    // BAD: the text typed by the user is part of the command line
    Runtime.getRuntime().exec("ping " + ip.text.toString())
}
```

## References

- OWASP: [Command Injection](https://owasp.org/www-community/attacks/Command_Injection).
- OWASP: [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Common Weakness Enumeration: [CWE-88](https://cwe.mitre.org/data/definitions/88.html).
