const jwt = require("jsonwebtoken");
const { sign } = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;
const SIGN_OPTIONS = { algorithm: "HS256", expiresIn: "15m" };
const NO_EXPIRY_OPTIONS = { algorithm: "HS256" };

function noOptions(user) {
  return jwt.sign({ sub: user.id }, SECRET); // $ Alert
}

function optionsWithoutExpiresIn(user) {
  return jwt.sign({ sub: user.id, role: user.role }, SECRET, { algorithm: "HS256" }); // $ Alert
}

function callbackOnly(user, cb) {
  jwt.sign({ sub: user.id }, SECRET, function (err, token) {
    cb(err, token);
  }); // $ Alert
}

function localOptionsWithoutExpiresIn(user) {
  const opts = { algorithm: "RS256", issuer: "auth" };
  return jwt.sign({ sub: user.id }, SECRET, opts); // $ Alert
}

function destructuredSign(user) {
  return sign({ sub: user.id }, SECRET); // $ Alert
}

function moduleOptionsWithoutExpiresIn(user) {
  return jwt.sign({ sub: user.id }, SECRET, NO_EXPIRY_OPTIONS); // $ Alert
}

// SAFE: `expiresIn` option.
function withExpiresIn(user) {
  return jwt.sign({ sub: user.id }, SECRET, { expiresIn: "1h" });
}

// SAFE: `expiresIn` option together with a callback.
function withExpiresInCallback(user, cb) {
  jwt.sign({ sub: user.id }, SECRET, { expiresIn: 3600 }, cb);
}

// SAFE: `exp` claim in the payload.
function withExpClaim(user) {
  return jwt.sign({ sub: user.id, exp: Math.floor(Date.now() / 1000) + 3600 }, SECRET);
}

// SAFE: shared options object with `expiresIn`.
function withSharedOptions(user) {
  return jwt.sign({ sub: user.id }, SECRET, SIGN_OPTIONS);
}

// SAFE (unknown): options computed elsewhere.
function withUnknownOptions(user, options) {
  return jwt.sign({ sub: user.id }, SECRET, options);
}

// SAFE: options spread may contain `expiresIn`.
function withSpreadOptions(user, defaults) {
  return jwt.sign({ sub: user.id }, SECRET, { ...defaults, algorithm: "HS256" });
}

// SAFE: verification is not token issuance.
function verify(token) {
  return jwt.verify(token, SECRET);
}

module.exports = {
  noOptions,
  optionsWithoutExpiresIn,
  callbackOnly,
  localOptionsWithoutExpiresIn,
  destructuredSign,
  moduleOptionsWithoutExpiresIn,
  withExpiresIn,
  withExpiresInCallback,
  withExpClaim,
  withSharedOptions,
  withUnknownOptions,
  withSpreadOptions,
  verify,
};
