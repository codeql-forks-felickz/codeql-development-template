# Credential buffer is not cleared before release

This query identifies a password passed to a Windows logon API that remains in a local array when its function returns or in a heap buffer when it is freed. Use a secure clearing function on the same buffer after authentication and before it is released.

The query recognizes `SecureZeroMemory`, `RtlSecureZeroMemory`, `memset_s`, and `explicit_bzero` as clearing operations. It currently matches the password use, clearing call, and release within one function, and uses source order to identify clearing after authentication.

## Known limitations

- Only `LogonUserA`, `LogonUserW`, `LogonUserExA`, and `LogonUserExW` are treated as credential uses.
- Only the listed clearing functions are recognized. Other clearing wrappers are not modeled.
- Local aliasing, interprocedural clearing, and complex control-flow ordering are not modeled.
- Stack buffers are identified as local arrays. Heap buffers are identified when the same password expression is passed to `free`.
