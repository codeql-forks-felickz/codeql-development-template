const jwt = require('jsonwebtoken');
const MongoClient = require('mongodb').MongoClient;

const SESSION_SECRET = process.env.SESSION_SECRET;

// The whole user document (including its `password` field) is signed into the token.
function authenticate(email, pass, res) {
  MongoClient.connect('mongodb://db:27017/app', function (err, db) {
    db.collection('users').findOne({ email: email, password: pass }, function (err, result) { // $ Source
      if (result !== null) {
        const user = result;
        const payload = { user };
        const token = jwt.sign(payload, SESSION_SECRET); // $ Alert
        res.json({ token: token });
      }
    });
  });
}

// Safe: only non-sensitive fields of the user document are signed.
function authenticateSafe(email, pass, res) {
  MongoClient.connect('mongodb://db:27017/app', function (err, db) {
    db.collection('users').findOne({ email: email, password: pass }, function (err, result) {
      if (result !== null) {
        const payload = { id: result._id, email: result.email, isAdmin: result.is_admin };
        const token = jwt.sign(payload, SESSION_SECRET);
        res.json({ token: token });
      }
    });
  });
}

// Safe: the projection excludes the password field from the returned record.
function authenticateProjected(email, pass, res) {
  MongoClient.connect('mongodb://db:27017/app', function (err, db) {
    db.collection('users').findOne(
      { email: email, password: pass },
      { projection: { password: 0 } },
      function (err, result) {
        if (result !== null) {
          const token = jwt.sign({ user: result }, SESSION_SECRET);
          res.json({ token: token });
        }
      },
    );
  });
}

// Safe: there is no indication that a `posts` document contains credentials.
function sharePost(slug, res) {
  MongoClient.connect('mongodb://db:27017/app', function (err, db) {
    db.collection('posts').findOne({ slug: slug }, function (err, post) {
      res.json({ token: jwt.sign({ post }, SESSION_SECRET) });
    });
  });
}

module.exports = { authenticate, authenticateSafe, authenticateProjected, sharePost };
