# Flask configuration objects, loaded with `app.config.from_object(...)`


class ProductionConfig:
    SESSION_COOKIE_SECURE = True  # GOOD
    SESSION_COOKIE_HTTPONLY = True  # GOOD


class DevelopmentConfig:
    SESSION_COOKIE_SECURE = False  # BAD: session cookie sent over plain HTTP
    SESSION_COOKIE_HTTPONLY = False  # BAD: session cookie readable by JavaScript
