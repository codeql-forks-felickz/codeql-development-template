# Django logout view exposed to GET requests

Routing Django's `logout_then_login` view directly allows a cross-site GET request to end an authenticated user's session. Django's CSRF middleware does not validate safe-method requests such as GET.

## Recommendation

Require an explicit POST request for logout and include CSRF protection on the logout form.

## Known limitations

This query covers direct routes to Django's `logout_then_login` view. It does not infer equivalent behavior from custom logout handlers.
