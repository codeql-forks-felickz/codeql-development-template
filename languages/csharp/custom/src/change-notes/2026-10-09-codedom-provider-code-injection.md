---
category: newQuery
---

- Added a new query, `cs/code-injection-codedom-provider`, which detects user-controlled source text compiled with `CodeDomProvider.CompileAssemblyFromSource` (for example via `CSharpCodeProvider` or `VBCodeProvider`). The standard `cs/code-injection` query only models `ICodeCompiler.CompileAssemblyFromSource*`, which `CodeDomProvider` does not implement, and a Models-as-Data sink cannot cover the expanded `params string[] sources` arguments.
