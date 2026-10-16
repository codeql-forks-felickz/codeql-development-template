# Arbitrary file access during archive extraction ("Zip Slip") with extended models

This query is a variant of the standard `js/zipslip` query. It reuses the standard sources, sinks and sanitizers, and adds the following models:

- **`unzipper.Open`**: entry paths read from the central directory returned by `unzipper.Open.buffer`, `file`, `url`, `s3`, `s3_v3` and `custom` (for example `for (const entry of directory.files) { entry.path }`) are treated as untrusted archive entry names.
- **`adm-zip` before 0.4.11**: `extractAllTo`, `extractAllToAsync` and `extractEntryTo` do not sanitize entry names in these versions (CVE-2018-1002204). Calls on an archive created by `AdmZip(...)` or `new AdmZip(...)` are reported when the nearest `package.json` pins an exact `adm-zip` version older than 0.4.11. Version ranges such as `^0.4.7` are not reported, because they may resolve to a fixed release.

## Recommendation

Resolve each entry path against the extraction directory and verify that the result stays inside that directory (for example with `path.resolve` followed by a `startsWith(root + path.sep)` check) before writing. A substring check such as `absolutePath.includes(root)` is not sufficient. Upgrade `adm-zip` to 0.4.11 or later.

## Example

```javascript
const directory = await unzipper.Open.buffer(buffer)
for (const entry of directory.files) {
  // BAD: entry.path may contain '..'
  fs.createWriteStream('uploads/' + entry.path)
}
```

```javascript
const root = path.resolve(dest)
for (const entry of directory.files) {
  const target = path.resolve(root, entry.path)
  // GOOD: target is checked to be inside the extraction directory
  if (target.startsWith(root + path.sep)) {
    fs.createWriteStream(target)
  }
}
```

## References

- Snyk: [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability).
- NVD: [CVE-2018-1002204 (adm-zip)](https://nvd.nist.gov/vuln/detail/CVE-2018-1002204).
- Common Weakness Enumeration: [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
