"use strict";

const express = require("express");
const session = require("express-session");
const MongoClient = require("mongodb").MongoClient;
const app = express();
const routes = require("./routes");

MongoClient.connect("mongodb://localhost/db", (err, db) => {
  app.use(session({ secret: "secret", saveUninitialized: true, resave: true }));
  routes(app, db);
  app.listen(4000);
});
