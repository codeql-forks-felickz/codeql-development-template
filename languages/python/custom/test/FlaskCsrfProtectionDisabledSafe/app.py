from flask import Flask, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.route("/change", methods=["POST"])
def change():
    session["changed"] = True
