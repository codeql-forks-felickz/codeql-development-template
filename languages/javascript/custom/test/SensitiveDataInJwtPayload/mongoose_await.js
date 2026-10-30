const jwt = require('jsonwebtoken');
const jwtSimple = require('jwt-simple');
const { SignJWT } = require('jose');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const User = mongoose.model('User', new mongoose.Schema({ email: String, password: String }));
const JWT_SECRET = process.env.JWT_SECRET;

// The user document is known to hold a password hash, which is signed into the token.
async function login(req, res) {
  const user = await User.findOne({ email: req.body.email }); // $ Source
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.sendStatus(401);
  }
  res.json({ token: jwt.sign({ user }, JWT_SECRET) }); // $ Alert
}

async function loginJwtSimple(req, res) {
  const account = await User.findOne({ email: req.body.email }); // $ Source
  if (!account || !(await bcrypt.compare(req.body.password, account.password))) {
    return res.sendStatus(401);
  }
  res.json({ token: jwtSimple.encode({ account }, JWT_SECRET) }); // $ Alert
}

async function loginJose(req, res) {
  const user = await User.findOne({ email: req.body.email }); // $ Source
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.sendStatus(401);
  }
  const token = await new SignJWT({ user }) // $ Alert
    .setProtectedHeader({ alg: 'HS256' })
    .sign(new TextEncoder().encode(JWT_SECRET));
  res.json({ token });
}

// A password-like value is placed directly in the payload.
function register(req, res) {
  const password = req.body.password; // $ Source
  const token = jwt.sign({ email: req.body.email, password }, JWT_SECRET); // $ Alert
  res.json({ token });
}

// Safe: only identifiers are signed.
async function loginSafe(req, res) {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.sendStatus(401);
  }
  res.json({ token: jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET) });
}

// Safe: the password field is stripped from the record before signing.
async function loginWithoutPassword(req, res) {
  const user = await User.findOne({ email: req.body.email }).lean();
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.sendStatus(401);
  }
  const { password, ...profile } = user;
  res.json({ token: jwt.sign({ profile }, JWT_SECRET) });
}

// Safe: the password is only used as the signing key argument, not in the payload.
function signWithPassword(req, res) {
  res.json({ token: jwt.sign({ email: req.body.email }, req.body.password) });
}

module.exports = { login, loginJwtSimple, loginJose, register, loginSafe, loginWithoutPassword, signWithPassword };
