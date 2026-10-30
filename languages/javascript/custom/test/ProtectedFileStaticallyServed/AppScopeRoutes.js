const express = require("express");
const router = express.Router();

router.get("/", requireLogin, (req, res) => {
  res.render("account.html"); // NOT OK: mounted router inherits app settings and static middleware
});

function requireLogin(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}

module.exports = router;
