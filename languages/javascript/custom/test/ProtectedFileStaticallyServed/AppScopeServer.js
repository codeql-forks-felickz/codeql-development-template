const express = require("express");

const app = express();
app.set("views", "scope/static/views");
app.use(express.static("scope/static"));
app.use("/account", require("./AppScopeRoutes"));

const unrelatedApp = express();
unrelatedApp.use(express.static("scope/private-views"));
const privateViewsApp = express();
privateViewsApp.set("views", "scope/private-views");
privateViewsApp.get("/private", requireLogin, (req, res) => {
  res.render("account.html"); // OK: the matching static middleware belongs to another app
});

const defaultViewsApp = express();
defaultViewsApp.use(express.static("views"));
defaultViewsApp.get("/dashboard", requireLogin, (req, res) => {
  res.render("dashboard.html"); // NOT OK: default views are served by this app
});

function requireLogin(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}
