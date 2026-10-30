const jose = require("node-jose");

exports.handler = (event, context, callback) => {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  const tokenSections = authHeader.split(".");
  // BAD: identity derived by base64url-decoding the token payload without verification
  const authData = jose.util.base64url.decode(tokenSections[1]); // $ Alert
  const token = JSON.parse(authData);
  const user = token.username;
  callback(null, { statusCode: 200, body: JSON.stringify({ user: user }) });
};
