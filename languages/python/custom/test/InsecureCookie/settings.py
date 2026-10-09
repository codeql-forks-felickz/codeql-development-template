# Django settings module

SESSION_COOKIE_HTTPONLY = False  # BAD: session cookie readable by JavaScript
SESSION_COOKIE_SECURE = False  # BAD: session cookie sent over plain HTTP
CSRF_COOKIE_SECURE = False  # BAD: CSRF cookie sent over plain HTTP

# GOOD: Django documents that `HttpOnly` on the CSRF cookie offers no practical protection,
# and many applications deliberately leave it readable by JavaScript.
CSRF_COOKIE_HTTPONLY = False

SESSION_COOKIE_AGE = 1209600  # GOOD: unrelated setting


def configure():
    SESSION_COOKIE_SECURE = False  # GOOD: local variable, not a settings assignment
    return SESSION_COOKIE_SECURE
