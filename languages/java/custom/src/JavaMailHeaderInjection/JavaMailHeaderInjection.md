# Email header injection

Untrusted input written to an outgoing JavaMail message subject or header can allow an attacker to inject additional email headers if the mail implementation accepts newline characters.

This query covers `setSubject`, `setHeader`, and `addHeader` calls on `javax.mail.Message` and `jakarta.mail.Message` implementations. It reuses the remote input sources and newline-removal barriers from `java/http-response-splitting`. Mail implementations and versions may differ in how they encode or reject header values, so findings should be checked against the application’s mail stack.

## Recommendation

Validate subject and header values against an allow-list where possible. Otherwise, reject carriage return, line feed, and any other characters the configured mail implementation may interpret as line breaks.

## Example

```java
void send(HttpServletRequest request) throws MessagingException {
  String subject = request.getParameter("subject");
  Message message = new MimeMessage(session);
  message.setSubject(subject, "UTF-8"); // BAD
}
```

```java
void send(HttpServletRequest request) throws MessagingException {
  String subject = request.getParameter("subject").replaceAll("[\r\n]", "");
  Message message = new MimeMessage(session);
  message.setSubject(subject, "UTF-8"); // GOOD
}
```

## References

- CWE-93: [Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html)
