# Flask cookie-authenticated route without CSRF protection

Flask's session cookie is sent automatically by browsers. A route that accepts an unsafe HTTP method and uses that session can therefore be triggered cross-site unless the application validates a CSRF token.

This query reports routes with an explicit unsafe method (`POST`, `PUT`, `PATCH` or `DELETE`) that use Flask's `session` or `g.session`, when no Flask-WTF `CSRFProtect` instance is created in the analyzed source.

## Recommendation

Register and initialize Flask-WTF's `CSRFProtect` extension for the application, and include a CSRF token in forms that submit unsafe requests.

## Known limitations

The query recognizes Flask-WTF's `CSRFProtect` constructor and does not model custom token validation or protection configured outside the analyzed code. A constructor in a multi-application database can suppress results for unrelated applications.
