SECRET_KEY = "secret"  # $ Alert

INSTALLED_APPS = [
    "django.contrib.auth",
    "rest_framework_simplejwt",
]

SIMPLE_JWT = {
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
}

OTHER_JWT = {
    "SIGNING_KEY": "unrelated-dict",
}
