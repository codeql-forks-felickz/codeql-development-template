const { Sequelize, DataTypes } = require("sequelize");
const express = require("express");

const sequelize = new Sequelize("sqlite::memory:");

// A model defined with `sequelize.define` that stores the password as is.
const Login = sequelize.define("Login", {
    email: DataTypes.STRING,
    password: DataTypes.STRING
});

// Safe: a `hooks` option may hash the password.
const HookedLogin = sequelize.define("HookedLogin", {
    email: DataTypes.STRING,
    password: DataTypes.STRING
}, { hooks: { beforeCreate: (login) => { login.password = hash(login.password); } } });

function hash(p) { return p; }

const app = express();
app.post("/logins", async (req, res) => {
    await Login.create(req.body); // $ Alert
    await HookedLogin.create(req.body);
    res.end();
});
