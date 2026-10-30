const jwt = require("jwt-simple");

const JWT_PRIV = process.env.JWT_PRIV;

// Reduced from an access-token generator: the payload has no `exp` claim.
function generateJwtAccessToken(username, userid, roles) {
  var jwtToken = {
    username: username,
    userid: userid,
    roles: roles == null ? [] : roles,
  };

  return jwt.encode(jwtToken, JWT_PRIV, "RS256"); // $ Alert
}

function inlinePayload(username) {
  return jwt.encode({ sub: username }, JWT_PRIV, "RS256"); // $ Alert
}

// The payload literal reaches the encode call through a helper.
function encodeClaims(claims) {
  return jwt.encode(claims, JWT_PRIV, "HS256"); // $ Alert
}

function issueWithoutExpiry(username) {
  return encodeClaims({ sub: username });
}

// SAFE: payload has an `exp` claim.
function generateWithExp(username) {
  var payload = {
    username: username,
    exp: Math.floor(Date.now() / 1000) + 15 * 60,
  };
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

// SAFE: `exp` is assigned after the payload is created.
function generateWithExpAssignedLater(username) {
  var payload = { username: username };
  payload.exp = Math.floor(Date.now() / 1000) + 15 * 60;
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

function addExpiry(claims) {
  claims.exp = Math.floor(Date.now() / 1000) + 15 * 60;
  return claims;
}

// SAFE: `exp` is added by a helper that mutates the payload.
function generateWithExpHelperMutation(username) {
  var payload = { username: username };
  addExpiry(payload);
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

// SAFE: `exp` is added by a helper that returns the payload.
function generateWithExpHelperReturn(username) {
  return jwt.encode(addExpiry({ username: username }), JWT_PRIV, "RS256");
}

// SAFE: `exp` is set through Object.assign.
function generateWithObjectAssign(username) {
  var payload = { username: username };
  Object.assign(payload, { exp: Math.floor(Date.now() / 1000) + 60 });
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

// SAFE: spread may contribute an `exp` claim.
function generateWithSpread(base) {
  return jwt.encode({ ...base, sub: "x" }, JWT_PRIV, "RS256");
}

// SAFE: computed property may be `exp`.
function generateWithComputed(key, value) {
  return jwt.encode({ [key]: value }, JWT_PRIV, "RS256");
}

// SAFE (unknown): payload is not constructed locally.
function passthrough(payload) {
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

// SAFE: decoding is not token issuance.
function decode(token) {
  return jwt.decode(token, JWT_PRIV);
}

module.exports = {
  generateJwtAccessToken,
  inlinePayload,
  issueWithoutExpiry,
  generateWithExp,
  generateWithExpAssignedLater,
  generateWithExpHelperMutation,
  generateWithExpHelperReturn,
  generateWithObjectAssign,
  generateWithSpread,
  generateWithComputed,
  passthrough,
  decode,
};
