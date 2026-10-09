# Improper control of generation of code via CodeDomProvider

If the source text passed to `CodeDomProvider.CompileAssemblyFromSource` (for example via `CSharpCodeProvider` or `VBCodeProvider`) is built from user-controlled data, an attacker can inject arbitrary code that is compiled and executed in the application's process.

The standard `cs/code-injection` query only models `ICodeCompiler.CompileAssemblyFromSource*`. `CodeDomProvider` does not implement `ICodeCompiler`, so calls made directly on a provider instance are not reported by that query. This query reports only those `CodeDomProvider` calls, so it can run alongside `cs/code-injection` without duplicate alerts.

## Recommendation

Avoid compiling code built from user input. If dynamic behavior is required, parse the input into a constrained form (for example a number, or an expression tree evaluated by a restricted interpreter) and never splice raw input into source text.

## Example

```csharp
string expression = reader.ReadLine();
string src = "class Calc { public int Run() { return " + expression + "; } }";
// BAD: user input is compiled as code.
new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), src);

// GOOD: input is parsed as an integer before being used.
int value = int.Parse(reader.ReadLine());
string safeSrc = "class Calc { public int Run() { return " + value + "; } }";
new CSharpCodeProvider().CompileAssemblyFromSource(new CompilerParameters(), safeSrc);
```

## References

- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Common Weakness Enumeration: [CWE-96](https://cwe.mitre.org/data/definitions/96.html).
