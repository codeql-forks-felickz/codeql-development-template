# Password received from a socket is used without decryption

This query identifies data received directly into a buffer by `recv` or `recvfrom` and later passed to a Windows logon API as its password argument. It does not infer whether TLS or another transport protection is active; use the result to review the socket and protocol handling.

An in-place call to `CryptDecrypt` or `CryptUnprotectMemory` is treated as a barrier.

## Known limitations

- Only `recv` and `recvfrom` and the four `LogonUser`/`LogonUserEx` A/W variants are modeled. Other socket APIs and authentication functions are not covered.
- TLS termination and custom encryption are not inferred. The query only suppresses flow through the two in-place decryption APIs listed above.
