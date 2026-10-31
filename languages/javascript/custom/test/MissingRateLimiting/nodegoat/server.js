"use strict";

const express = require("express");
const MongoClient = require("mongodb").MongoClient;
const app = express();
const routes = require("./routes");

MongoClient.connect("mongodb://localhost/db", (err, db) => {
  routes(app, db);
  app.listen(4000);
});
