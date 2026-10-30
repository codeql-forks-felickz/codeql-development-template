# Android FileProvider shares the device root directory

`androidx.core.content.FileProvider` generates `content://` URIs for files listed in an XML paths
configuration (usually `res/xml/file_paths.xml` or `res/xml/provider_paths.xml`). The undocumented
`<root-path>` entry resolves paths relative to the file system root. When it uses `path="/"` (or an
empty path), the provider can produce URIs for, and grant URI permissions to, any file the
application can read, including its private databases, shared preferences and tokens in
`/data/data/<package>/`. Combined with intent redirection or a component that returns
attacker-chosen URIs with `FLAG_GRANT_READ_URI_PERMISSION`, this allows other applications to read
or overwrite private application files.

## Recommendation

Remove `<root-path>` entries. Share only the narrowest directory required, using entries such as
`<files-path>`, `<cache-path>` or `<external-files-path>` with a specific sub-directory.

## Example

The following configuration shares the whole file system:

```xml
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <root-path name="root" path="/" />
</paths>
```

The following configuration only shares a dedicated sub-directory of the application cache:

```xml
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <cache-path name="shared_images" path="images/" />
</paths>
```

## References

- Android Developers: [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider).
- Android Developers: [Improperly exposed directories to FileProvider](https://developer.android.com/privacy-and-security/risks/file-providers).
- Common Weakness Enumeration: [CWE-668](https://cwe.mitre.org/data/definitions/668.html).
- Common Weakness Enumeration: [CWE-200](https://cwe.mitre.org/data/definitions/200.html).
