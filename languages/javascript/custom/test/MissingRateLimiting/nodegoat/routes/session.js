// Login handler defined as a `this.x = ...` property of a constructor function; the
// credentials are verified by a DAO method (reduced from a NodeGoat-style application).
const UserDAO = require("../user-dao").UserDAO;

function SessionHandler(db) {
  "use strict";

  const userDAO = new UserDAO(db);

  this.handleLoginRequest = (req, res, next) => {
    const { userName, password } = req.body;
    userDAO.validateLogin(userName, password, (err, user) => {
      if (err) return next(err);
      req.session.userId = user._id;
      return res.redirect("/dashboard");
    });
  };

  this.displayLoginPage = (req, res) => {
    return res.render("login");
  };
}

module.exports = SessionHandler;
