# LDAP query built from user-controlled sources

If an LDAP search filter or distinguished name is built from user-controlled data without escaping LDAP special characters (such as `*`, `(`, `)`, `\`, and NUL), a malicious user may be able to change the meaning of the query, for example to match every entry or to bypass intended search restrictions.

## Recommendation

Escape user input before including it in an LDAP search filter (RFC 4515) or distinguished name (RFC 4514), or validate it against a strict allowlist.

## Example

The following example reads a name from the console and inserts it directly into an LDAP filter. Input such as `*)(objectClass=*` changes the filter semantics.

```c
fgets(data, sizeof(data), stdin);
_snprintf(filter, sizeof(filter) - 1, "(cn=%s)", data);
ldap_search_ext_sA(ld, "base", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &msg);
```

## Data extensions

The sinks for this query are defined as `ldap-injection` `sinkModel` rows in the `languages-cpp-custom-models` model pack (`languages/cpp/custom/models/cwe-90.model.yml`). They cover the Win32 (`Wldap32`) and OpenLDAP `ldap_search*` functions. Add further rows of kind `ldap-injection` to extend coverage, or `barrierModel` rows of kind `ldap-injection` to model escaping functions.

## References

- CWE-90: [Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html).
- Microsoft: [ldap_search_ext_s function (winldap.h)](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_search_ext_s).
- RFC 4515: [LDAP String Representation of Search Filters](https://www.rfc-editor.org/rfc/rfc4515).
