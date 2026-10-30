const express = require('express');

const app = express();

function authCheck(req, res, next) {
  if (!req.session.user) return res.sendStatus(401);
  next();
}

// Upstream behavior: a case-sensitive middleware path.
app.use(/\/foo\/.*/, authCheck); // $ Alert

app.get('/foo/bar', (req, res) => {
  res.send('bar');
});
