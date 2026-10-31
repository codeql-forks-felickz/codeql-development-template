# COMPLIANT: CSRF protection is provided by django-session-csrf.
MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "session_csrf.CsrfMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
)
