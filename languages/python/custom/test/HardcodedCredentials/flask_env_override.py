import os
from flask import Flask

# GOOD: the literal is only a development default; the same key is also
# assigned from the environment, so it is not reported.
app = Flask(__name__)
app.secret_key = "development-key"
if os.environ.get("PRODUCTION"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]

# GOOD: default value of an environment read
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "fallback-key")
