# Code injection via JavaScript ScriptEngine

The `javax.script.ScriptEngine` API (for example Nashorn, Rhino or GraalJS) executes script source with full access to the Java runtime. If a script is built from user-controlled data, such as an HTTP request parameter, and then passed to `ScriptEngine.eval` or `Compilable.compile`, an attacker can inject arbitrary script code. Because these engines can call into Java classes, this typically results in remote code execution.

## Recommendation

Do not build script source from user-controlled data. If user data must be made available to a script, pass it as a binding value (for example with `ScriptEngine.put` or a `Bindings` object) and keep the script source constant. If the data is expected to be a simple value, convert it to a primitive type such as `int` or `boolean` before use. For JSON input, parse it with a JSON library instead of evaluating it as script.

## Example

The following example interpolates a request parameter into JavaScript source and evaluates it. An attacker can supply a value such as `1; java.lang.Runtime.getRuntime().exec("...")` to run arbitrary commands.

```java
String js = "var o = " + request.getParameter("jsonString") + ";";
engine.eval(js); // BAD
```

The following example keeps the script source constant and passes the user data as a binding value instead.

```java
engine.put("input", request.getParameter("jsonString"));
engine.eval("JSON.parse(input)"); // GOOD
```

## References

- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Oracle: [Java Scripting Programmer's Guide](https://docs.oracle.com/en/java/javase/11/scripting/java-scripting-programmers-guide.pdf).
- OWASP: [Code Injection](https://owasp.org/www-community/attacks/Code_Injection).
