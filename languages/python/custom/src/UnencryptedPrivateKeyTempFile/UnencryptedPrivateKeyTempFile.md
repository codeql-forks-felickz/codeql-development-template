# Unencrypted private key written to a shared temporary directory

Directories such as `/tmp`, `/var/tmp`, and `/dev/shm` are shared by all local users. Writing an unencrypted private key to a fixed path there with `open()` creates the file with default permissions (typically world-readable), and the predictable name lets another user pre-create the file or a symbolic link to capture or redirect the key. Anyone who obtains the key can impersonate the service or sign certificates with it.

This query reports private keys serialized without encryption (`private_bytes(..., encryption_algorithm=NoEncryption())` from `cryptography`, or `OpenSSL.crypto.dump_privatekey` without a cipher) that are written to a file whose path is a literal under `/tmp`, `/var/tmp`, or `/dev/shm`, or is derived from `tempfile.gettempdir()`.

## Recommendation

Store private keys in a dedicated directory that only the owning user can access, create the file with restrictive permissions (for example `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)`), and encrypt the key with a passphrase (`BestAvailableEncryption`) where possible. If a temporary file is really needed, use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()`, which create a unique file with mode `0600`.

## Example

The following code writes an unencrypted CA key to `/tmp/ca.key`:

```python
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
with open('/tmp/ca.key', 'wb') as out:
    out.write(pem_private)
```

Encrypt the key and write it to a private location with restrictive permissions instead:

```python
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
)
fd = os.open(os.path.join(key_dir, "ca.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as out:
    out.write(pem_private)
```

## References

- Common Weakness Enumeration: [CWE-522](https://cwe.mitre.org/data/definitions/522.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Common Weakness Enumeration: [CWE-377](https://cwe.mitre.org/data/definitions/377.html).
