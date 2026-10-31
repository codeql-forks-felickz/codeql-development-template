// A global session authentication guard installed directly with `app.use`.
var express = require('express');
var cookieParser = require('cookie-parser');

var app = express();
app.use(cookieParser()); // $ Alert

function requireLogin(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.redirect('/login');
}
app.use(requireLogin);

app.post('/transfer', function (req, res) {
  transfer(req.body.to, req.body.amount);
  res.sendStatus(204);
}); // $ RelatedLocation
