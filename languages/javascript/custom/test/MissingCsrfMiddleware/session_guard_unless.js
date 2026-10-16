// Session authentication is enforced by a global guard wrapped with `express-unless`,
// and `csurf` is only mounted after the route handlers, so it never runs for them.
var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('client-sessions');
var csurf = require('csurf');
var unless = require('express-unless');

var app = express();
app.use(cookieParser()); // $ Alert
app.use(session({ cookieName: 'session', secret: 'not-a-real-secret' }));

var admin_check = function (req, res, next) {
  if (req.session.user.is_admin) {
    next();
  } else {
    res.status(403).json({ message: 'not admin' });
  }
};
admin_check.unless = unless;
app.use(admin_check.unless({ path: /^(?!\/admin).*/ }));

app.post('/admin/money', function (req, res) {
  updateBalance(Number(req.body.userid), 500);
  res.json({ ok: true });
}); // $ RelatedLocation

// Safe HTTP methods are not flagged.
app.get('/admin/users', function (req, res) {
  res.json(listUsers());
});

app.use(csurf({ cookie: true }));
