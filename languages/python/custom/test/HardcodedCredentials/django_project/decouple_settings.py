from decouple import config

# GOOD: python-decouple reads the value from the environment / .env file
SECRET_KEY = config("SECRET_KEY", default="insecure-dev-key")
