# Uncontrolled request data in resource handling

Request data (query string, form fields, headers, action parameters, or the client-supplied name of an uploaded file) must not directly control how the application handles system resources. This query reports request data that reaches one of the following operations without validation:

- **Database connection settings (CWE-15).** Concatenating request data into a connection string passed to a `DbConnection`/`IDbConnection` constructor or `ConnectionString` property, or passing it to `ChangeDatabase`, lets an attacker pick an arbitrary account or catalog and inject additional `key=value;` pairs.
- **Search-path environment variables (CWE-427).** Setting `PATH`, `LD_LIBRARY_PATH`, and similar variables via `Environment.SetEnvironmentVariable` from request data lets an attacker direct executable and library resolution to a directory they control.
- **Loop bounds (CWE-400).** Using a request-controlled number as the limit of a loop (for example, the number of writes to a file) lets an attacker exhaust CPU or disk.
- **Allocation sizes (CWE-789).** Using a request-controlled number as an array length or collection capacity (`ArrayList`, `List<T>`, `StringBuilder`, and so on) lets an attacker exhaust memory.
- **Uploads under the web root (CWE-434).** Saving an uploaded file under the web root (`Server.MapPath(...)`, `IWebHostEnvironment.WebRootPath`) using the client-supplied file name, without checking the extension, lets an attacker upload and then request an executable file such as an `.aspx` web shell.

## Recommendation

- Build connection strings with `SqlConnectionStringBuilder` (or the provider-specific builder) from fixed configuration, and never let the request select the account or catalog.
- Never set search-path environment variables from request data.
- Check numeric request values against a fixed upper bound (for example, `if (count > 0 && count <= 100)`) or clamp them with `Math.Min`/`Math.Clamp` before using them as loop limits or allocation sizes.
- Store uploads outside the web root, generate the stored file name on the server (for example, `Path.GetRandomFileName()`), and validate the extension against an allow list.

## Example

The following ASP.NET Web Forms handler saves an uploaded file under the web root using the client-supplied name:

```csharp
string filename = Path.GetFileName(FileUpload1.FileName);
FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename); // BAD
```

The following handler only saves files with an allowed extension:

```csharp
string filename = Path.GetFileName(FileUpload1.FileName);
string ext = Path.GetExtension(filename).ToLowerInvariant();
if (ext == ".png" || ext == ".jpg")
{
    FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename); // GOOD
}
```

The following handler uses a request value as the number of writes without an upper bound:

```csharp
int count = int.Parse(req.QueryString["id"]);
for (int i = 0; i < count; i++) // BAD
{
    sw.WriteLine("Hello");
}
```

## References

- CWE-15: [External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html).
- CWE-400: [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html).
- CWE-427: [Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html).
- CWE-434: [Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html).
- CWE-789: [Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html).
- OWASP: [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
