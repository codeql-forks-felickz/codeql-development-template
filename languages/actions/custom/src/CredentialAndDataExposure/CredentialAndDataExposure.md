# Encoded secret written to workflow log

GitHub Actions masks the values of secrets when they appear in workflow logs. Masking only works on the exact registered value: if a workflow encodes or otherwise transforms a secret (for example with `base64`, `base32`, `xxd`, `od`, `hexdump`, `rev` or `openssl base64`) and prints the result, the runner does not recognize the transformed value and writes it to the log in clear. Anyone who can read the workflow logs (for public repositories, anyone at all) can decode it and recover the secret.

This query reports `run` steps using a Bash shell where a secret (`${{ secrets.* }}`, `${{ toJSON(secrets) }}` or `${{ github.token }}`, used inline, through an environment variable, or through a shell variable assigned from one) is piped into an encoding command whose output reaches the log, that is, it is not redirected to a file, captured in a variable or command substitution, or consumed by another command.

## Recommendation

Do not print secrets, or values derived from secrets, to the workflow log. If an encoded form of a secret is needed, capture it in a variable and register it with the `::add-mask::` workflow command before using it, and pass it to the consuming command through a file or standard input instead of printing it.

## Example

The following workflow prints a Base64-encoded secret. Masking does not apply to the encoded value, so the secret is exposed:

```yaml
- name: Get secret
  env:
    SUPER_SECRET: ${{ secrets.SUPER_SECRET }}
  run: echo "$SUPER_SECRET" | base64
```

The encoded value should instead be masked and consumed without printing it:

```yaml
- name: Use secret
  env:
    SUPER_SECRET: ${{ secrets.SUPER_SECRET }}
  run: |
    ENCODED=$(echo "$SUPER_SECRET" | base64 -w0)
    echo "::add-mask::$ENCODED"
    echo "$ENCODED" | docker login -u user --password-stdin
```

## References

- GitHub Docs: [Using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions).
- GitHub Docs: [Masking a value in a log](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#masking-a-value-in-a-log).
- Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
