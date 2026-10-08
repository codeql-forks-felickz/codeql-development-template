import os
from flask import Flask

# GOOD: read from the environment
app5 = Flask(__name__)
app5.secret_key = os.environ["FLASK_SECRET_KEY"]
app5.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app5.config.update(SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"))
