SESSION_ENGINE = "django.contrib.sessions.backends.db"

# COMPLIANT: session data is stored server-side, not in a client-controlled cookie
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
