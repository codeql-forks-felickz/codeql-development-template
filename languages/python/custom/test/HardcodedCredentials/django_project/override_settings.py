import os
import environ

# GOOD: development default overridden from the environment in the same module
SECRET_KEY = "insecure-dev-key"
if "DJANGO_SECRET_KEY" in os.environ:
    SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

env = environ.Env()
SIMPLE_JWT = {"SIGNING_KEY": "insecure-jwt-key"}
SIMPLE_JWT = {"SIGNING_KEY": env("JWT_SIGNING_KEY")}
