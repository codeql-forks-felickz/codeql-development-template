---
category: newQuery
---

- Added `py/custom/django-logout-on-get`, which reports direct routes to Django's `logout_then_login` view because cross-site GET requests can end an authenticated user's session.
- Added `py/custom/flask-csrf-protection-disabled`, which reports unsafe Flask routes that use cookie-backed sessions when Flask-WTF `CSRFProtect` is not registered.
- Added `py/custom/aiohttp-csrf-protection-disabled`, which reports aiohttp applications configured with session middleware but without CSRF middleware when an unsafe route is registered.
