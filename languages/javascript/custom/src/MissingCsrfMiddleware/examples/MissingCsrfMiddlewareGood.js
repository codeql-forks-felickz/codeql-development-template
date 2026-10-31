var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('client-sessions');
var csurf = require('csurf');

var app = express();
app.use(cookieParser());
app.use(session({ cookieName: 'session', secret: process.env.SESSION_SECRET }));
app.use(csurf({ cookie: true }));

// Session authentication guard for every route.
app.use(function (req, res, next) {
  if (req.session.authenticated) return next();
  res.redirect('/login');
});

app.post('/transfer', function (req, res) {
  transfer(req.body.to, req.body.amount);
  res.sendStatus(204);
});
