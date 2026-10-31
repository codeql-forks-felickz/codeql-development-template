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

function addExpiryWithAssign(claims) {
  Object.assign(claims, { exp: Math.floor(Date.now() / 1000) + 15 * 60 });
}

// SAFE: `exp` is added by a helper with `Object.assign`.
function generateWithObjectAssignHelper(username) {
  var payload = { username: username };
  addExpiryWithAssign(payload);
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

function assignExpiry(claims) {
  Object.assign(claims, { exp: Math.floor(Date.now() / 1000) + 15 * 60 });
}

function addExpiryWithNestedAssign(claims) {
  assignExpiry(claims);
}

// SAFE: a nested helper adds `exp` with `Object.assign`.
function generateWithNestedObjectAssignHelper(username) {
  var payload = { username: username };
  addExpiryWithNestedAssign(payload);
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

function addComputedProperty(claims, key) {
  claims[key] = "value";
}

// SAFE: a helper writes an unknown computed property.
function generateWithComputedPropertyHelper(username, key) {
  var payload = { username: username };
  addComputedProperty(payload, key);
  return jwt.encode(payload, JWT_PRIV, "RS256");
}

function addIssuer(claims) {
  claims.iss = "auth-service";
}

// The helper only adds `iss`, so the missing `exp` must still be reported.
function generateWithoutExpHelperMutation(username) {
  var payload = { username: username };
  addIssuer(payload);
  return jwt.encode(payload, JWT_PRIV, "RS256"); // $ Alert
}

function addStandardClaims(claims) {
  claims.iss = "auth-service";
  addExpiry(claims);
}

// SAFE: `exp` is added by a helper that delegates to another helper.
function generateWithNestedExpHelper(username) {
  var payload = { username: username };
  addStandardClaims(payload);
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
  generateWithObjectAssignHelper,
  generateWithNestedObjectAssignHelper,
  generateWithComputedPropertyHelper,
  generateWithoutExpHelperMutation,
  generateWithNestedExpHelper,
  generateWithExpHelperReturn,
  generateWithObjectAssign,
  generateWithSpread,
  generateWithComputed,
  passthrough,
  decode,
};
