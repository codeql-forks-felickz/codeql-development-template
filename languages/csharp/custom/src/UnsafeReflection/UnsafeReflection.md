# Use of externally-controlled input to select classes or code

Reflection APIs such as `Type.GetType`, `Assembly.GetType`, `Assembly.CreateInstance`, `Activator.CreateInstance(string, string)` and `AppDomain.CreateInstanceAndUnwrap` look up a type (and sometimes load an assembly) by name at run time. If that name comes from a user, the user can choose any type that can be loaded by the application. Instantiating it runs the type's constructor, static initializer and any other code that the application then calls on the object, which can lead to unexpected behavior, information disclosure, or code execution.

## Recommendation

Do not let users choose arbitrary type or assembly names. Map user input to a fixed set of known types (for example with a dictionary from a user-visible key to a `Type`), or check the name against an explicit allow list before resolving it.

## Example

The following program resolves a type named on the command line and creates an instance of it:

```csharp
Type type = Type.GetType(Environment.GetCommandLineArgs()[1]);
var surprise = Activator.CreateInstance(type!);
```

Instead, map the input to a known set of types:

```csharp
static readonly Dictionary<string, Type> Plugins = new()
{
    ["csv"] = typeof(CsvExporter),
    ["json"] = typeof(JsonExporter),
};

if (Plugins.TryGetValue(args[0], out var type))
{
    var exporter = Activator.CreateInstance(type);
}
```

## Notes

The query uses the active threat models. Command-line arguments, environment variables and console input are `local` sources, so they are only reported when the `local` threat model is enabled.

## References

- Common Weakness Enumeration: [CWE-470](https://cwe.mitre.org/data/definitions/470.html).
- OWASP: [Unsafe use of Reflection](https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection).
