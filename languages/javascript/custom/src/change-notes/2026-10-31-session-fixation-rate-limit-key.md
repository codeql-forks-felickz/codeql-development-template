---
category: minorAnalysis
---

- Added a custom variant of the `js/session-fixation` query (`SessionFixation/SessionFixation.ql`). In addition to the standard query, it tracks the `req.session` object across function calls, so a login route that passes the session to a helper which marks it as authenticated (without calling `regenerate`) is now reported.
- Added a new query, `js/rate-limit-spoofable-key` (`RateLimitSpoofableKey/RateLimitSpoofableKey.ql`), which finds `express-rate-limit` and `express-slow-down` limiters whose `keyGenerator` derives the client key from a client address header such as `X-Forwarded-For`, or from `req.ip`/`req.ips` while the Express application that installs the limiter trusts all proxies (`app.enable('trust proxy')`).
