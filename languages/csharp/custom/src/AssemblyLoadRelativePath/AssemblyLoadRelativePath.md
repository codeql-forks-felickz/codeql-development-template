# File-like assembly identity or relative assembly path

`Assembly.Load` and `Assembly.LoadWithPartialName` interpret their string argument as an assembly identity, not as a file path. For example, `Assembly.Load("x.dll")` does not load the file `x.dll`; it requests the identity `x.dll` and probes for an assembly such as `x.dll.dll`. A file-like identity is therefore reported as probable misuse, rather than as a path-based load of the named file.

`Assembly.LoadFrom` and `Assembly.UnsafeLoadFrom` accept paths. Relative paths are resolved against the current directory, so an attacker who can write to that location may plant a malicious assembly whose code then runs with the privileges of the application.

Unlike `cs/assembly-path-injection`, which reports assembly paths that depend on user input, this query reports file-like names passed to identity-based loaders as probable misuse and relative paths passed to path-based loaders. It is an audit query for untrusted search path issues (CWE-426).

## Recommendation

Load assemblies by full path built from a trusted root (for example `Path.Combine(AppContext.BaseDirectory, "plugin.dll")`), or load them by strong-named assembly identity.

## Example

```csharp
string libraryName = "test.dll";
Assembly.Load(libraryName); // BAD: requests the assembly identity "test.dll", not the file test.dll
```

```csharp
Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "test.dll")); // GOOD
```

## References

- Microsoft Learn: [Best practices for assembly loading](https://learn.microsoft.com/dotnet/framework/deployment/best-practices-for-assembly-loading).
- Common Weakness Enumeration: [CWE-426](https://cwe.mitre.org/data/definitions/426.html).
- Common Weakness Enumeration: [CWE-114](https://cwe.mitre.org/data/definitions/114.html).
