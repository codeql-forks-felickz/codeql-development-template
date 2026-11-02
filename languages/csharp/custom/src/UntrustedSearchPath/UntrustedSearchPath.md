# Process started without a fully qualified path

When a program is started with `Process.Start`, `new ProcessStartInfo(...)` or by setting `ProcessStartInfo.FileName` to a bare name such as `ls` or `cmd.exe`, the operating system locates the executable by searching the directories in the `PATH` environment variable (and, on Windows, the application and current directories). If an attacker can place a file with the same name earlier in that search order, their program runs instead of the intended one, with the privileges of the application.

## Recommendation

Start external programs by their fully qualified path, for example `/bin/ls` or `C:\Windows\System32\cmd.exe`, or build the path from a trusted location such as `Environment.SystemDirectory`.

## Example

In the following example, the command is started by its bare name, so it is resolved through the search path:

```csharp
var startInfo = new ProcessStartInfo();
startInfo.FileName = "ls";
startInfo.Arguments = "-la";
Process.Start(startInfo);
```

Use the full path to the executable instead:

```csharp
var startInfo = new ProcessStartInfo();
startInfo.FileName = "/bin/ls";
startInfo.Arguments = "-la";
Process.Start(startInfo);
```

## Notes

Names with a non-executable file extension (for example `readme.txt`) are not reported, since they are normally documents opened through a file association rather than programs looked up on the search path.

## References

- Common Weakness Enumeration: [CWE-426](https://cwe.mitre.org/data/definitions/426.html).
- Common Weakness Enumeration: [CWE-427](https://cwe.mitre.org/data/definitions/427.html).
- Microsoft: [ProcessStartInfo.FileName](https://learn.microsoft.com/dotnet/api/system.diagnostics.processstartinfo.filename).
