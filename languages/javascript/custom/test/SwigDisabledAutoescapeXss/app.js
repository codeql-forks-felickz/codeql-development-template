const express = require("express");
const swig = require("swig");

swig.setDefaults({ autoescape: false });

const app = express();
app.post("/login", (req, res) => {
  res.render("login", { username: req.body.username }); // $ Source[js/swig-disabled-autoescape-xss]
});
