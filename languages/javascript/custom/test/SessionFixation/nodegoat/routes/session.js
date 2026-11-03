const UserDAO = require("../user-dao").UserDAO;
// Handlers defined as `this.x = ...` properties of a constructor function, with the
// session write inside a callback (reduced from a NodeGoat-style application).
function SessionHandler(db) {
  const userDAO = new UserDAO(db);
  "use strict";

  this.handleLoginRequest = (req, res, next) => {
    const { userName, password } = req.body;
    userDAO.validateLogin(userName, password, (err, user) => {
      if (err) return next(err);
      req.session.userId = user._id;
      return res.redirect("/dashboard");
    });
  };

  // GOOD: the session is regenerated before the user ID is stored.
  this.handleSafeLoginRequest = (req, res, next) => {
    const { userName, password } = req.body;
    userDAO.validateLogin(userName, password, (err, user) => {
      if (err) return next(err);
      req.session.regenerate(() => {
        req.session.userId = user._id;
        return res.redirect("/dashboard");
      });
    });
  };

  this.displayLoginPage = (req, res) => {
    return res.render("login");
  };
}

module.exports = SessionHandler;
