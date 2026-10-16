# languages-java-custom-models

Data extension (Models as Data) pack that adds rows to `codeql/java-all`.
Use it with stock queries via `--model-packs=languages-java-custom-models`
(plus `--additional-packs=languages/java/custom/models` when running locally).

## Models

| File                                         | Kind             | Effect                                                                                                                                                                          |
| -------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ldap/org.apache.directory.filter.model.yml` | `ldap-injection` | Treats the filter string passed to Apache Directory `FilterParser.parse` (ApacheDS 1.5.x `shared-ldap` and Apache Directory LDAP API) as a `java/ldap-injection` (CWE-90) sink. |

Tests: `languages/java/custom/test/SqlLdapInjectionCoverage`.
