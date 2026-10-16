# Uncontrolled data used in path expression (extended)

Accessing files using paths constructed from user-controlled data can allow an attacker to access unexpected resources, for example by using `..` segments or absolute paths to read or overwrite files outside of the intended directory.

This query extends the standard `cs/path-injection` query. It uses the same sources, sinks and sanitizers, with the following differences:

- Null checks (`x != null`, `x == null`, `x is null`, `x is not null`), comparisons of a character with the NUL character, and checks that only inspect a single character or the `Length` of a path are not treated as path validation.
- `char` values are not treated as sanitized, so a path that is rebuilt character by character keeps its taint.
- Sinks of kind `path-injection` from models-as-data (for example the `StreamReader(string)` constructors modeled in `languages-csharp-custom-models`) are included.

## Recommendation

Validate user input before using it to construct a file path. Prefer an allow-list of known file names, or use `Path.GetFileName` and check that the fully-qualified path (`Path.GetFullPath`) stays inside the intended directory.

## Example

```csharp
string filename = Request.QueryString["filename"];
if (filename != null)
{
    // BAD: a null check does not prevent `../../Web.config`.
    using var file = new FileStream(MapPath("~/Downloads/" + filename), FileMode.Open);
}
```

```csharp
string filename = Request.QueryString["filename"];
// GOOD: only known file names are accepted.
if (AllowedDownloads.Contains(filename))
{
    using var file = new FileStream(MapPath("~/Downloads/" + filename), FileMode.Open);
}
```

## References

- OWASP: [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).
- Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-23](https://cwe.mitre.org/data/definitions/23.html).
