// Negative cases: CSRF protection is mounted before the session-guarded routes,
// or the guard does not depend on cookie/session state.
var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('client-sessions');
var csurf = require('csurf');
var unless = require('express-unless');

(function () {
  var app = express();
  app.use(cookieParser());
  app.use(session({ cookieName: 'session', secret: 'not-a-real-secret' }));
  app.use(csurf({ cookie: true }));

  var admin_check = function (req, res, next) {
    if (req.session.user.is_admin) next();
    else res.sendStatus(403);
  };
  admin_check.unless = unless;
  app.use(admin_check.unless({ path: /^(?!\/admin).*/ }));

  app.post('/admin/money', function (req, res) {
    updateBalance(Number(req.body.userid), 500);
    res.json({ ok: true });
  });
})();

(function () {
  var app = express();
  app.use(cookieParser());

  // Header-based token authentication does not rely on ambient cookies.
  function requireApiKey(req, res, next) {
    if (req.headers['x-api-key'] === process.env.API_KEY) return next();
    res.sendStatus(401);
  }
  app.use(requireApiKey);

  app.post('/api/transfer', function (req, res) {
    transfer(req.body.to, req.body.amount);
    res.sendStatus(204);
  });
})();
