# Reflective instantiation of a user-selected class

Mapping a request value (for example a `command` parameter) to a class name and then
loading and instantiating that class through reflection lets the client choose which code
runs on the server. Adding a fixed package prefix or class-name suffix narrows, but does not
remove, the set of reachable classes, and every class that matches the pattern, now or in a
future release, becomes an entry point.

The query reports a `Constructor.newInstance`, `Class.newInstance` or `Method.invoke` call
whose `Class`, `Constructor` or `Method` was obtained via `Class.forName` or
`ClassLoader.loadClass` from a remote (active threat model) source, unless the value was
first checked against an allowlist (`Collection.contains`, `Map.containsKey`,
`String.equals`/`equalsIgnoreCase` or `String.matches`).

## Recommendation

Do not derive class names from user input. Use a fixed lookup table that maps the accepted
values to the classes (or to factories), or validate the value against an explicit allowlist
before any reflective lookup.

## Example

The following code builds a class name from the `command` request parameter and instantiates it:

```java
String command = request.getParameter("command");
Class<?> cmdClass = Class.forName("com.example.commands." + ucfirst(command) + "Command");
Command cmd = (Command) cmdClass.getDeclaredConstructor(String.class).newInstance(user);
```

Use a lookup table instead:

```java
private static final Map<String, Supplier<Command>> COMMANDS =
    Map.of("listen", ListenCommand::new, "ignore", IgnoreCommand::new);

Supplier<Command> factory = COMMANDS.get(request.getParameter("command"));
if (factory != null) {
  factory.get().execute(user);
}
```

## References

- OWASP: [Unsafe use of Reflection](https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection).
- Common Weakness Enumeration: [CWE-470](https://cwe.mitre.org/data/definitions/470.html).
