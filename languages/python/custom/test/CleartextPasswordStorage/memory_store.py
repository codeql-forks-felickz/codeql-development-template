from flask import Flask, flash, redirect, request

app = Flask(__name__)

users = {
    "admin": {
        "password": "admin123",  # $ Alert
        "role": "admin",
    },
}


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")  # $ Source
    if username not in users:
        users[username] = {
            "password": password,  # $ Alert
            "role": "user",
        }
    return redirect("/")


@app.route("/change", methods=["POST"])
def change():
    new_password = request.form.get("new_password")  # $ Source
    users[request.form["username"]]["password"] = new_password  # $ Alert
    return redirect("/")


# --- Safe cases ---

from werkzeug.security import generate_password_hash

settings = {"database": {"password": "not-a-user-store"}}


@app.route("/register_hashed", methods=["POST"])
def register_hashed():
    password = request.form.get("password")
    users[request.form["username"]] = {"password": generate_password_hash(password)}
    return redirect("/")


def login_payload(password):
    # Safe: a local request payload, not a stored user record.
    payload = {"username": "bob", "password": password}
    return payload


# Seed accounts that store password hashes, not clear text.
HASHED_USERS = {
    "alice": {"password": "491a2800b80719ea9e3c89ca5472a8bda1bdd1533d4574ea5bd85b70a8e93be0"},
    "bob": {"password": "pbkdf2_sha256$600000$abc$def"},
}
