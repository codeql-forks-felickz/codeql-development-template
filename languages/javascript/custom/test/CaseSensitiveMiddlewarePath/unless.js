const express = require('express');
const unless = require('express-unless');

const app = express();

const adminCheck = function (req, res, next) {
  if (req.session.user.is_admin) {
    next();
  } else {
    res.status(403).json({ message: 'not admin' });
  }
};
adminCheck.unless = unless;

// Skips `adminCheck` for every path that does not start with lower-case `/admin`,
// so `/ADMIN/users` is not checked but still reaches the `/admin/users` route.
app.use(adminCheck.unless({ path: /^(?!\/admin).*/ })); // $ Alert

app.get('/admin/users', function (req, res) {
  res.send('admin users');
});

const app2 = express();

// Case-insensitive exclusion: not vulnerable.
app2.use(adminCheck.unless({ path: /^(?!\/admin).*/i }));

app2.get('/admin/users', function (req, res) {
  res.send('admin users');
});

const app3 = express();

// Exclusion pattern inside a `path` array.
app3.use(adminCheck.unless({ path: ['/login', /^(?!\/(admin|internal)\/).*/] })); // $ Alert

app3.get('/internal/stats', function (req, res) {
  res.send('stats');
});

const app4 = express();

// Positive exclusion of public paths: a differently cased path is still checked
// (fails closed), so this is not a bypass.
app4.use(adminCheck.unless({ path: [/^\/public\//, '/login'] }));

app4.get('/admin/users', function (req, res) {
  res.send('admin users');
});

app4.get('/public/info', function (req, res) {
  res.send('info');
});

const app5 = express();

// The character-class alternative keeps the recased path from matching the exclusion.
app5.use(adminCheck.unless({ path: /^(?!\/admin|\/[A-Z]).*/ }));

app5.get('/admin/users', function (req, res) {
  res.send('admin users');
});

const app6 = express();

// The string entry already excludes the endpoint path.
app6.use(adminCheck.unless({ path: ['/admin/users', /^(?!\/admin).*/] }));

app6.get('/admin/users', function (req, res) {
  res.send('admin users');
});

const app7 = express();

// The sibling regexp already excludes the endpoint path.
app7.use(adminCheck.unless({ path: [/^\/admin\/users$/, /^(?!\/admin).*/] }));

app7.get('/admin/users', function (req, res) {
  res.send('admin users');
});
