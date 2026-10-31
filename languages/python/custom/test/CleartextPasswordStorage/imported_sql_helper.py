from flask import request

from sqlite_helper import query_db


def create_user():
    username = request.form.get("username")
    password = request.form.get("password")  # $ Source
    access_level = request.form.get("access_level")
    query = (
        "INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)"
        % (username, password, int(access_level))  # $ Alert
    )
    query_db(query, [], True)


def create_user_safely():
    username = request.form.get("username")
    password = request.form.get("password")
    query = "INSERT INTO user (username, password) VALUES ('%s', '%s')" % (
        username,
        generate_password_hash(password),
    )
    query_db(query, [], True)


def generate_password_hash(password):
    return password
