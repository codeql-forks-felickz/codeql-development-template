// Admin login handler that looks up the submitted credentials in the database
// (reduced from a nodejs-goof-style application).
var mongoose = require('mongoose');
var User = mongoose.model('User');

exports.loginHandler = function (req, res, next) {
  User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
    if (users.length > 0) {
      req.session.loggedIn = 1;
      return res.redirect('/admin');
    }
    return res.status(401).send();
  });
};

exports.login = function (req, res) {
  return res.render('admin', { granted: false });
};
