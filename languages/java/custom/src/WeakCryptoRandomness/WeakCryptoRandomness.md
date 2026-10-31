# Insecure randomness used for one-time password or security token

Non-cryptographic pseudo-random number generators such as `java.util.Random`, `java.util.concurrent.ThreadLocalRandom` and `Math.random()` produce predictable output. An attacker who observes a few outputs, or who can guess the seed (for example the current time), can predict later values.

If such a generator produces a one-time password (OTP), a verification or reset code, or a security token (session, CSRF, reset, API or access token), an attacker may predict the value and bypass authentication or take over accounts.

This query complements `java/insecure-randomness`. It shares that query's sources of insecure randomness. Its sinks are values assigned to, passed as, or returned under names that indicate a one-time password, verification code or security token (for example `otp`, `generateOtp`, `setOtpHash`, `verificationCode`, `resetToken`, `sessionId`). It does not report results that `java/insecure-randomness` already reports.

## Recommendation

Use a cryptographically secure generator such as `java.security.SecureRandom` to generate one-time passwords, verification codes and security tokens.

## Example

In the following example, a one-time password is generated with `java.util.Random`, so its value is predictable:

```java
Random random = new Random();
String otp = String.format("%06d", random.nextInt(1000000));
```

The following example uses `SecureRandom` instead:

```java
SecureRandom random = new SecureRandom();
String otp = String.format("%06d", random.nextInt(1000000));
```

## References

- OWASP: [Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness).
- OWASP: [Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-330](https://cwe.mitre.org/data/definitions/330.html).
- Common Weakness Enumeration: [CWE-338](https://cwe.mitre.org/data/definitions/338.html).
