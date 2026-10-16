const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const app = express();
const router = express.Router();

// Everything below `static/` is public, including the view templates.
app.use(express.static('static'));
app.set('views', 'static/views');
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

router.get("/admin", verifyJWT, (req, res) => {
  res.status(200).render("admin.html"); // NOT OK: also served as /views/admin.html
});

router.get("/dashboard", requireLogin, function (req, res) {
  res.render("dashboard"); // NOT OK: view name without extension
});

router.get("/report", ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "static", "reports", "q3.html")); // NOT OK: also served as /reports/q3.html
});

router.get("/settings", isAdmin, (req, res) => {
  res.sendFile("settings.html", { root: "static/admin-page" }); // NOT OK: also served as /admin-page/settings.html
});

router.get("/account", passport.authenticate("jwt", { session: false }), (req, res) => {
  res.render("account.html"); // NOT OK
});

router.get("/login", (req, res) => {
  res.render("login.html"); // OK: not protected by authentication middleware
});

router.get("/about", logRequest, (req, res) => {
  res.render("about.html"); // OK: middleware is not an authentication check
});

router.get("/private", verifyJWT, (req, res) => {
  res.sendFile(path.join(__dirname, "private", "secret.html")); // OK: `private` is not served
});

router.get("/internal", verifyJWT, (req, res) => {
  res.sendFile(path.join(__dirname, "static", ".internal", "tools.html")); // OK: dotfiles are not served
});

router.get("/page", verifyJWT, (req, res) => {
  res.render(req.query.page); // OK: view name is not a constant
});

app.use('/', router);
app.listen(8080);

function verifyJWT(req, res, next) {
  const token = req.cookies.sessionToken;
  if (!token) return res.status(401).send({ auth: false });
  jwt.verify(token, process.env.SECRET, function (err, decoded) {
    if (err) return res.status(500).send({ auth: false });
    req.userId = decoded.id;
    next();
  });
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.sendStatus(401);
}

function isAdmin(req, res, next) {
  if (req.user && req.user.role === "admin") return next();
  res.sendStatus(403);
}

function logRequest(req, res, next) {
  console.log(req.method, req.url);
  next();
}
