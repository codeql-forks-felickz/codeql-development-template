# Swift credential and data exposure coverage

Custom Swift queries that extend the stock CodeQL Swift catalog for credential and data exposure gaps (CWE-200, CWE-311, CWE-312, CWE-319, CWE-321).

Swift has no data extension (`extensible` predicate) support, so all models are written in QL in `CredentialAndDataExposure.qll` and plug into the stock extension points (`SinkModelCsv`, `*AdditionalFlowStep`, `CleartextStorageDatabaseSink`).

| Query                                        | CWE       | Gap closed                                                                                                                                                                                                                 |
| -------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `swift/custom/hardcoded-key`                 | 321       | CommonCrypto `CCCrypt`/`CCCryptor*` key arguments are sinks; flow through stored properties, `withUnsafeBytes` closures and `baseAddress`; hard-coded literals in global/static property initializers (which have no CFG). |
| `swift/custom/static-initialization-vector`  | 329, 1204 | Same as above for the CommonCrypto IV argument.                                                                                                                                                                            |
| `swift/custom/cleartext-transmission`        | 319       | Stock flow plus a step from initializer arguments of source-declared request model structs (for example `SignInModel(email:password:)`) to the constructed value, so Alamofire `parameters:` are tracked.                  |
| `swift/custom/cleartext-storage-database`    | 312       | Stock flow plus a sink for property writes on objects created by `NSEntityDescription.insertNewObject(forEntityName:into:)`, independent of resolving the `NSManagedObject` subclass.                                      |
| `swift/custom/base64-as-encryption`          | 311, 327  | New query: parameters of `encrypt`-named functions that only reach `base64EncodedString`/`base64EncodedData` without any real crypto call.                                                                                 |
| `swift/custom/request-headers-untrusted-url` | 200, 601  | New query: remote input (for example `launchOptions?[.url]`) used as the URL of a `URLRequest` that gets custom headers (such as `Authorization`) before being loaded.                                                     |

## Testing

Swift extraction is only supported on macOS, so the tests must be run there:

```sh
cd languages/swift/custom/test
codeql test run -- CredentialAndDataExposure/
```

On Linux, only compilation can be checked:

```sh
cd languages/swift/custom
codeql query compile --check-only -- src/CredentialAndDataExposure/ test/CredentialAndDataExposure/
```
