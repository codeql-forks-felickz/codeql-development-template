// The session object is passed to a helper that marks it as logged in
// (reduced from a nodejs-goof-style application).
var mongoose = require('mongoose');
var User = mongoose.model('User');

exports.loginHandler = function (req, res, next) {
  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
    if (users.length > 0) {
      const session = req.session;
      return adminLoginSuccess(req.body.redirectPage, session, res);
    }
    return res.status(401).send();
  });
};

function adminLoginSuccess(redirectPage, session, res) {
  session.loggedIn = 1;
  return res.redirect(redirectPage || '/admin');
}

// GOOD: the session is regenerated in the helper.
exports.safeLoginHandler = function (req, res, next) {
  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
    if (users.length > 0) {
      return safeLoginSuccess(req.session, res);
    }
    return res.status(401).send();
  });
};

function safeLoginSuccess(session, res) {
  session.regenerate(function () {
    session.loggedIn = 1;
    return res.redirect('/admin');
  });
}

exports.logout = function (req, res) {
  req.session.loggedIn = 0;
  req.session.destroy(function () {
    return res.redirect('/');
  });
};
