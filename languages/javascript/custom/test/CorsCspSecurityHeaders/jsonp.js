const express = require('express');
const app = express();

app.get('/session-profile', (req, res) => {
  const profile = { name: req.session.username, email: req.session.email };
  res.jsonp(profile); // $ Alert
});

app.get('/passport-profile', function (req, res) {
  res.jsonp({ id: req.user.id, email: req.user.email }); // $ Alert
});

app.get('/signed-cookie', function (req, res) {
  const account = lookupAccount(req.signedCookies.sid);
  res.jsonp(account); // $ Alert
});

app.get('/cookie-header', function (req, res) {
  const account = lookupAccount(req.headers.cookie);
  res.jsonp(account); // $ Alert
});

// OK: public, non-credentialed data may be served as JSONP.
app.get('/public-config', function (req, res) {
  res.jsonp({ version: '1.0.0', name: req.query.name });
});

// OK: authenticated data served as plain JSON.
app.get('/private-json', function (req, res) {
  res.json({ email: req.session.email });
});

// OK: JSONP of a constant value, even in an authenticated handler.
app.get('/ping', function (req, res) {
  if (!req.session.username) return res.sendStatus(401);
  res.jsonp('pong');
});

// OK: a third-party script cannot issue a POST request to this handler.
app.post('/post-only-profile', function (req, res) {
  res.jsonp({ email: req.session.email });
});

// Middleware is reachable through GET requests.
app.use('/middleware-profile', function (req, res) {
  res.jsonp({ email: req.session.email }); // $ Alert
});

// `all` handles GET requests as well as other methods.
app.all('/all-profile', function (req, res) {
  res.jsonp({ email: req.session.email }); // $ Alert
});

function sharedPostAndGetProfile(req, res) {
  res.jsonp({ email: req.session.email }); // $ Alert
}

app.post('/shared-profile', sharedPostAndGetProfile);
app.get('/shared-profile', sharedPostAndGetProfile);

function lookupAccount(key) {
  return { key };
}

app.listen(3000);
