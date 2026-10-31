const express = require('express');
const jwt = require('jsonwebtoken');
const { NextResponse } = require('next/server');


const app = express();
const router = express.Router();

// State-rebuild middleware returned by an exported helper.
exports.rebuildState = () => (req, res, next) => {
  const token = req.cookies.token;
  jwt.verify(token, process.env.JWT_PUBLIC_KEY, (err, decoded) => {
    if (!err && decoded) {
      res.cookie('token', token);
      res.cookie('token', token, { httpOnly: true });
    }
  });
  next();
};
app.use(exports.rebuildState());

// Login route with a chained response.
app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.user }, process.env.JWT_SECRET);
  res.cookie('sessionToken', token).redirect('/home');
  res.cookie('sessionToken', token, { httpOnly: true }).redirect('/home');
});

// Router login with a nested authentication callback.
router.post('/login', (req, res) => {
  jwt.verify(req.body.token, process.env.JWT_PUBLIC_KEY, (err, user) => {
    if (!err) {
      const token = jwt.sign(user, process.env.JWT_SECRET);
      res.cookie('authSessionToken', token).redirect(301, '/home');
      res.cookie('authSessionToken', token, { httpOnly: true }).redirect(301, '/home');
    }
  });
});
app.use(router);

// Profile-update route returned by an exported helper.
exports.updateProfile = () => async (req, res, next) => {
  const token = jwt.sign(req.body, process.env.JWT_SECRET);
  res.cookie('token', token);
  res.cookie('token', token, { httpOnly: true });
  next();
};
app.post('/profile', exports.updateProfile());

// Control: a name recognized by the stock sensitivity heuristic.
app.get('/session', (req, res) => {
  const token = req.cookies.token;
  res.cookie('sessionId', token);
  res.cookie('sessionId', token, { httpOnly: true });
});

// Different APIs remain outside the client-sessions query's scope.
exports.POST = async (request) => {
  const data = await request.json();
  const res = NextResponse.json(data);
  res.cookies.set('jwt', data.jwt, { path: '/' });
  res.cookies.set('jwt', data.jwt, { path: '/', httpOnly: true });
  return res;
};
