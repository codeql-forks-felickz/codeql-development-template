const SessionHandler = require("./session");

const index = (app, db) => {
  "use strict";

  const sessionHandler = new SessionHandler(db);

  app.get("/login", sessionHandler.displayLoginPage);
  app.post("/login", sessionHandler.handleLoginRequest); // $ Alert
  app.post("/safe-login", sessionHandler.handleSafeLoginRequest);
};

module.exports = index;
