import os

# GOOD: read from the environment
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY")

SIMPLE_JWT = {
    "SIGNING_KEY": os.environ["JWT_SIGNING_KEY"],
}
