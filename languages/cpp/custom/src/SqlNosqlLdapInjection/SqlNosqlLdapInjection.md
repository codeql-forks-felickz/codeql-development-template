# LDAP query built from user-controlled sources

If an LDAP search filter is built from user-controlled data (for example data read from a socket with `recv`, a file or console with `fgets`, or an environment variable with `getenv`) without escaping LDAP metacharacters, a malicious user can change the meaning of the filter. This can disclose directory entries the user should not see or bypass LDAP-based authentication and authorization checks.

This query reports user-controlled data that reaches the search filter argument of the WinLDAP (`ldap_search*A`, `ldap_search*W`) and OpenLDAP (`ldap_search`, `ldap_search_s`, `ldap_search_st`, `ldap_search_ext`, `ldap_search_ext_s`) search functions, as well as `ldap_search_init_page`.

## Recommendation

Escape the special characters `*`, `(`, `)`, `\` and NUL in any user-controlled value before inserting it into a search filter (RFC 4515), for example with OpenLDAP's `ldap_bv2escaped_filter_value`, or validate the value against a strict allow-list. Values converted to an integer before use are not reported.

## Example

The following code copies data received from a socket into an LDAP search filter. An attacker can send `*)(objectClass=*` to retrieve every entry in the directory:

```c
char data[256];
char filter[256];
int n = recv(sock, data, sizeof(data) - 1, 0);
data[n] = '\0';
_snprintf(filter, sizeof(filter) - 1, "(cn=%s)", data);
// BAD: user-controlled data in the search filter
ldap_search_ext_sA(ld, "base", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL,
                   LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
```

Escape the value before building the filter:

```c
struct berval in = { n, data }, out;
if (ldap_bv2escaped_filter_value(&in, &out) == 0) {
  // GOOD: the value is escaped
  snprintf(filter, sizeof(filter), "(cn=%s)", out.bv_val);
  ldap_search_ext_s(ld, "base", LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL,
                    NULL, LDAP_NO_LIMIT, &pMessage);
}
```

## References

- MITRE: [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
- OWASP: [LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- IETF: [RFC 4515: String Representation of Search Filters](https://www.rfc-editor.org/rfc/rfc4515)
