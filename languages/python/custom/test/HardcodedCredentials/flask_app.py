from flask import Flask


def create_app():
    app = Flask(__name__)
    app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"  # $ Alert
    return app


app2 = Flask(__name__)
app2.config["SECRET_KEY"] = "change-me-please"  # $ Alert

app3 = Flask(__name__)
app3.config.update(SECRET_KEY="dev")  # $ Alert

FLASK_SECRET = "s3cr3t"  # $ Alert
app4 = Flask(__name__)
app4.secret_key = FLASK_SECRET

# GOOD: empty strings are not reported
app6 = Flask(__name__)
app6.secret_key = ""

# GOOD: unrelated attribute / config key on a Flask app
app7 = Flask(__name__)
app7.name = "my-application"
app7.config["SESSION_COOKIE_NAME"] = "session"

# GOOD: not a Flask application
class Holder:
    pass


holder = Holder()
holder.secret_key = "not-a-flask-secret"
