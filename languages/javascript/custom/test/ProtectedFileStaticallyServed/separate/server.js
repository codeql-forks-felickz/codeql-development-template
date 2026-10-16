const express = require("express");
const path = require("path");
const app = express();

// Views live outside the served folder.
app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));

app.get("/admin", requireAuth, (req, res) => {
  res.render("admin.html"); // OK: `views` is not served
});

function requireAuth(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}
