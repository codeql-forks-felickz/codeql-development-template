const jwt = require("jsonwebtoken");

function issueAccessToken(user) {
  // BAD: the token has no `exp` claim and is valid forever
  return jwt.sign({ sub: user.id, roles: user.roles }, process.env.JWT_SECRET, {
    algorithm: "HS256",
  });
}
