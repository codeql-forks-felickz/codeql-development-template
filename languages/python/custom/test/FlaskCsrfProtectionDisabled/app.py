from flask import Flask, session

app = Flask(__name__)


@app.route("/change", methods=["POST"])  # $ Alert
def change():
    session["changed"] = True
