# Untrusted data in an ODBC data source name

Using a command-line value as the data source name passed to `SQLConnect` allows the caller to influence which ODBC data source is selected.

## Recommendation

Use a configured data source name or validate the input against an application-controlled allowlist before connecting.

## Known limitations

This query tracks command-line arguments only, and models only the data source name argument to `SQLConnect`. It does not analyze other ODBC connection APIs or prove whether a selected data source name is trusted.
