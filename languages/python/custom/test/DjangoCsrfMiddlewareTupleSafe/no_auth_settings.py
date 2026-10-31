# COMPLIANT: no session authentication middleware, so there is no ambient
# credential for a cross-site request to abuse.
MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
)
