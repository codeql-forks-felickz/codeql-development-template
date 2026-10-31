var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('express-session');

(function nodejsGoof() {
  var app = express();
  app.use(cookieParser()); // $ Alert
  app.use(session({ secret: process.env.SESSION_SECRET }));

  function isLoggedIn(req, res, next) {
    if (req.session.loggedIn) next();
    else res.redirect('/');
  }

  app.post(
    '/account_details',
    isLoggedIn, // $ RelatedLocation
    function (req, res) {
      saveAccountDetails(req.body);
      res.sendStatus(200);
    } // $ RelatedLocation
  );

  // This route is not guarded by the session check and does not use session state.
  app.post('/create', function (req, res) {
    createRecord(req.body);
    res.sendStatus(200);
  });
})();

(function nodeGoat() {
  var app = express();
  app.use(session({ secret: process.env.SESSION_SECRET })); // $ Alert

  var sessionHandler = {
    isLoggedInMiddleware: function (req, res, next) {
      if (req.session.userId) next();
      else res.redirect('/login');
    }
  };
  var profileHandler = {
    handleProfileUpdate: function (req, res) {
      var userId = req.session.userId;
      updateProfile(userId, req.body);
      res.sendStatus(200);
    }
  };

  function registerRoutes(app, sessionHandler, profileHandler) {
    var isLoggedIn = sessionHandler.isLoggedInMiddleware;
    app.post(
      '/profile',
      isLoggedIn, // $ RelatedLocation
      profileHandler.handleProfileUpdate // $ RelatedLocation
    );
    app.get('/profile', isLoggedIn, function (req, res) {
      res.json({ userId: req.session.userId });
    });
  }

  registerRoutes(app, sessionHandler, profileHandler);
})();

(function juiceShop() {
  var app = express();
  app.use(cookieParser()); // $ Alert

  function updateUserProfile() {
    return async function (req, res, next) {
      var user = authenticatedUsers.get(req.cookies.token);
      if (!user) return next(new Error('Unauthorized'));
      await updateUsername(user.id, req.body.username);
      res.sendStatus(200);
    };
  }

  app.post('/profile', updateUserProfile()); // $ RelatedLocation

  app.post('/api/profile', function (req, res) {
    if (!req.headers['x-api-key']) return res.sendStatus(401);
    updateUsername(req.body.id, req.body.username);
    res.sendStatus(200);
  });
})();
