# Assembly loaded from a relative file name

Calling `Assembly.Load` or `Assembly.LoadWithPartialName` with a file name such as `"test.dll"`, or `Assembly.LoadFrom` / `Assembly.UnsafeLoadFrom` with a relative path, makes the runtime resolve the assembly through the current working directory or the assembly probing paths. An attacker who can write to one of those locations can plant a matching assembly whose code then runs with the privileges of the application.

Unlike `cs/assembly-path-injection`, which reports assembly paths that depend on user input, this query reports constant relative names. It is an audit query for untrusted search path issues (CWE-426).

## Recommendation

Load assemblies by full path built from a trusted root (for example `Path.Combine(AppContext.BaseDirectory, "plugin.dll")`), or load them by strong-named assembly identity.

## Example

```csharp
string libraryName = "test.dll";
Assembly.Load(libraryName); // BAD: resolved through the probing path
```

```csharp
Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "test.dll")); // GOOD
```

## References

- Microsoft Learn: [Best practices for assembly loading](https://learn.microsoft.com/dotnet/framework/deployment/best-practices-for-assembly-loading).
- Common Weakness Enumeration: [CWE-426](https://cwe.mitre.org/data/definitions/426.html).
- Common Weakness Enumeration: [CWE-114](https://cwe.mitre.org/data/definitions/114.html).
