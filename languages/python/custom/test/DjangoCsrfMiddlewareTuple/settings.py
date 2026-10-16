# NON_COMPLIANT: `MIDDLEWARE` is a tuple with session authentication enabled but
# without `CsrfViewMiddleware` (commented out), so CSRF protection is disabled.
MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # 'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "app.middleware.CookieTokenAuthenticationMiddleware",  # $ Alert
)
