SECRET_KEY = "not-a-real-secret"

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

# NON_COMPLIANT: pickle-based session serializer with the signed-cookie session backend
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
