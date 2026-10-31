const express = require("express");
const swig = require("swig");

swig.setDefaults({ autoescape: true });

const app = express();
app.post("/login", (req, res) => {
  res.render("login", { username: req.body.username });
});
