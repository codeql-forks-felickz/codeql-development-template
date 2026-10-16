// `client-sessions` stores the session in a cookie; no cookie-parser is used.
var express = require('express');
var session = require('client-sessions');

var app = express();
app.use(session({ cookieName: 'session', secret: 'not-a-real-secret' })); // $ Alert

app.put('/profile', function (req, res) {
  updateProfile(req.session.user._id, req.body);
  res.sendStatus(204);
}); // $ RelatedLocation
