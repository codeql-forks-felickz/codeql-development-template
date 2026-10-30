const jwt = require("jsonwebtoken");

function issueAccessToken(user) {
  // GOOD: the token expires after 15 minutes
  return jwt.sign({ sub: user.id, roles: user.roles }, process.env.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "15m",
  });
}
