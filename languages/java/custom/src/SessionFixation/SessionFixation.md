# Session fixation after login

If an application authenticates a user and then stores the authenticated identity in the session it already had, the session identifier does not change at login. An attacker who can set or learn the victim's pre-login session identifier (for example through a crafted link, a sub-domain cookie or a shared computer) can keep using the same identifier after the victim logs in, and is then authenticated as the victim.

This query reports calls to `HttpServletRequest.getSession()` (or `getSession(true)`) whose session is used to store an authentication-related attribute (for example `user`, `isLoggedIn` or `authToken`) in a method that neither calls `HttpServletRequest.changeSessionId()` nor `HttpSession.invalidate()`.

## Recommendation

Renew the session identifier when the user's privilege level changes. Call `request.changeSessionId()` (Servlet 3.1 and later) after successful authentication, or invalidate the old session and create a new one. Frameworks such as Spring Security do this automatically.

## Example

```java
HttpSession session = request.getSession();      // BAD: reuses the pre-login session
session.setAttribute("user", username);

request.changeSessionId();                       // GOOD: new identifier after login
request.getSession().setAttribute("user", username);
```

## References

- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [OWASP Session Management Cheat Sheet: Renew the Session ID After Any Privilege Level Change](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change)
