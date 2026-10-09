const express = require('express');

function adminCheck(req, res, next) {
  if (req.session.user.is_admin) {
    next();
  } else {
    res.sendStatus(403);
  }
}

const app = express();

// Negated inline exclusion: requests whose path does not start with lower-case `/admin`
// skip the check, so `/ADMIN/settings` bypasses it.
app.use((req, res, next) => {
  if (!/^\/admin/.test(req.path)) return next(); // $ Alert
  adminCheck(req, res, next);
});

app.get('/admin/settings', (req, res) => {
  res.send('settings');
});

const app2 = express();

// Negative-lookahead inline exclusion, with a block statement.
app2.use(function (req, res, next) {
  if (/^(?!\/admin)/.test(req.originalUrl)) { // $ Alert
    return next();
  }
  adminCheck(req, res, next);
});

app2.get('/admin/settings', (req, res) => {
  res.send('settings');
});

const app3 = express();

// Case-sensitive exclusion of public paths: `/PUBLIC/...` and `/ADMIN/...` are still
// checked (fails closed), so this is not a bypass.
app3.use((req, res, next) => {
  if (/^\/(public|login)/.test(req.path)) return next();
  adminCheck(req, res, next);
});

app3.get('/admin/settings', (req, res) => {
  res.send('settings');
});

app3.get('/public/info', (req, res) => {
  res.send('info');
});

const app4 = express();

// Case-insensitive negated exclusion: not vulnerable.
app4.use((req, res, next) => {
  if (!/^\/admin/i.test(req.path)) return next();
  adminCheck(req, res, next);
});

app4.get('/admin/settings', (req, res) => {
  res.send('settings');
});

const app5 = express();

// The exclusion only calls `next()` without returning, so `adminCheck` still runs.
app5.use((req, res, next) => {
  if (!/^\/admin/.test(req.path)) next();
  adminCheck(req, res, next);
});

app5.get('/admin/settings', (req, res) => {
  res.send('settings');
});

const app6 = express();

// `next(); return;` inside the exclusion branch.
app6.use((req, res, next) => {
  if (!/^\/admin\//.test(req.url)) { // $ Alert
    next();
    return;
  }
  adminCheck(req, res, next);
});

app6.get('/admin/settings', (req, res) => {
  res.send('settings');
});
