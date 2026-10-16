# Unbounded outbound fetch or predictable shared temporary file

This query reports two resource-handling weaknesses that stock CodeQL Python queries do not cover:

1. **Outbound fetch without a timeout (CWE-400).** `requests` has no default timeout. A call such as `requests.get(url)` to a non-constant URL can block a worker forever if the server stalls. Reading the whole body with `response.content`, `.text` or `.json()` can also exhaust memory if the response is very large. Calls that pass `timeout=` (or `**kwargs`, which may carry one) and calls to a hard-coded URL literal are not reported.
2. **Predictable files in a shared temporary directory (CWE-377).** A path built from a literal under `/tmp`, `/var/tmp` or `/dev/shm`, such as `"/tmp/app.apikey." + user`, `os.path.join("/tmp", name)` or `Path("/tmp").glob(pattern)`, has a name that other local users can predict. They can list it, read it, create it first, or replace it. `py/insecure-temporary-file` only reports `tempfile.mktemp`, `os.tempnam` and `os.tmpnam`, so it misses these cases.

## Recommendation

- Always pass `timeout=` to `requests` calls. Cap the response size, for example by streaming with `stream=True` and reading at most N bytes with `iter_content`.
- Use `tempfile.mkstemp`, `tempfile.NamedTemporaryFile` or `tempfile.TemporaryDirectory` to get files that are unpredictable and readable only by their owner. Keep long-lived data such as API keys in an application-owned store, never in `/tmp`.

## Example

```python
# BAD: no timeout, no size limit
response = requests.get(image_url, stream=True)
data = base64.b64encode(response.content)

# GOOD
response = requests.get(image_url, timeout=5)

# BAD: anyone can list /tmp and read or pre-create the key file
Path('/tmp/app.apikey.{}.{}'.format(username, key)).touch()

# GOOD
fd, path = tempfile.mkstemp(prefix="upload_")
```

## References

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Requests: Timeouts](https://requests.readthedocs.io/en/latest/user/advanced/#timeouts)
