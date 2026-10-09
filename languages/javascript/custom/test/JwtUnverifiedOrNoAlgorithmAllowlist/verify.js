const express = require("express");
const expressJwt = require("express-jwt");
const { expressjwt } = require("express-jwt");
const jwt = require("jsonwebtoken");
const jws = require("jws");
const fs = require("fs");

const app = express();
const publicKey = fs.readFileSync("keys/jwt.pub", "utf8");
const rsaCert = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
-----END PUBLIC KEY-----`;
const hmacSecret = process.env.JWT_SECRET;

// BAD: public key without an algorithm allowlist (RS/HS confusion)
app.use(expressJwt({ secret: publicKey })); // $ Alert

// BAD: v7+ API, public key without an algorithm allowlist
app.use(expressjwt({ secret: rsaCert, credentialsRequired: true })); // $ Alert

// GOOD: algorithm allowlist present
app.use(expressJwt({ secret: publicKey, algorithms: ["RS256"] }));
app.use(expressjwt({ secret: rsaCert, algorithms: ["RS256"] }));

// GOOD: not a public key
app.use(expressJwt({ secret: hmacSecret }));

app.get("/a", (req, res) => {
  // BAD: public key and no options
  const claims = jwt.verify(req.query.token, publicKey); // $ Alert
  res.send(claims.sub);
});

app.get("/b", (req, res) => {
  // BAD: options without `algorithms`
  const claims = jwt.verify(req.query.token, publicKey, { issuer: "me" }); // $ Alert
  res.send(claims.sub);
});

app.get("/c", (req, res) => {
  // GOOD: algorithm allowlist
  const claims = jwt.verify(req.query.token, publicKey, { algorithms: ["RS256"] });
  res.send(claims.sub);
});

app.get("/d", (req, res) => {
  // BAD: `jws.verify(signature, key)` trusts the algorithm in the token header
  if (jws.verify(req.query.token, publicKey)) { // $ Alert
    res.send("ok");
  }
});

app.get("/e", (req, res) => {
  // GOOD: `jws.verify(signature, algorithm, key)` pins the algorithm
  if (jws.verify(req.query.token, "RS256", publicKey)) {
    res.send("ok");
  }
});

module.exports = app;
