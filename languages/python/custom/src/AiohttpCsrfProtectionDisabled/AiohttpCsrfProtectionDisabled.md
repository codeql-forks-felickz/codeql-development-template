# aiohttp session middleware without CSRF middleware

aiohttp applications that use cookie-backed sessions need to validate CSRF tokens on state-changing requests. This query reports an `aiohttp.web.Application` configured with a `middlewares` list containing a session middleware but no middleware whose name identifies it as CSRF protection, when the project registers an unsafe route.

## Recommendation

Add CSRF validation middleware to the active application middleware list and validate the token on unsafe requests.

## Known limitations

This query recognizes middleware names containing `session` and `csrf`, and does not correlate a route with its specific application instance. Custom middleware with unrelated names is not modeled.
