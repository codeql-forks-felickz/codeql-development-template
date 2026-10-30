const express = require("express");
const jwt = require("jsonwebtoken");
const jwtDecode = require("jwt-decode");
const fs = require("fs");

const app = express();
const publicKey = fs.readFileSync("keys/jwt.pub", "utf8");
const secret = process.env.JWT_SECRET;

// BAD: identity derived from an unverified token
app.get("/profile", (req, res) => {
  const token = req.headers.authorization.replace("Bearer ", "");
  const claims = jwt.decode(token); // $ Alert
  res.send("Hello " + claims.username);
});

// BAD: identity derived from an unverified token via `jwt-decode`
app.get("/orders", (req, res) => {
  const user = jwtDecode(req.cookies.token); // $ Alert
  res.send(user.email);
});

// BAD: manual base64url decoding of the JWT payload
app.get("/manual", (req, res) => {
  const parts = req.get("Authorization").split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString()); // $ Alert
  res.send(payload.sub);
});

// GOOD: token is verified before it is decoded
app.get("/verified", (req, res) => {
  const token = req.headers.authorization;
  jwt.verify(token, secret, { algorithms: ["HS256"] });
  const claims = jwt.decode(token);
  res.send(claims.username);
});

// GOOD: token is verified (identity comes from the verified result)
app.get("/verified2", (req, res) => {
  const claims = jwt.verify(req.query.token, secret, { algorithms: ["HS256"] });
  res.send(claims.username);
});

function decodeAfterVerification(token) {
  jwt.verify(token, secret, { algorithms: ["HS256"] });
  return jwt.decode(token);
}

app.get("/verified-wrapper", (req, res) => {
  const claims = decodeAfterVerification(req.query.token); // $ MISSING: Alert
  res.send(claims.username);
});

app.get("/verified-manual", (req, res) => {
  const token = req.get("Authorization");
  jwt.verify(token, secret, { algorithms: ["HS256"] });
  const parts = token.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString()); // $ MISSING: Alert
  res.send(payload.sub);
});

// GOOD: decoding a token that is not attacker-controlled
const ownToken = jwt.sign({ sub: "service" }, secret, { algorithm: "HS256" });
console.log(jwt.decode(ownToken).sub);

module.exports = app;
