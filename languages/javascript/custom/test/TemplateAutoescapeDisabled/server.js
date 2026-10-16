const express = require("express");
const consolidate = require("consolidate");
const swig = require("swig");

const app = express();
app.engine(".html", consolidate.swig);
app.set("view engine", "html");

// Swig autoescaping is disabled for every template rendered by the app.
swig.setDefaults({
  autoescape: false // $ Alert
});

const strict = new swig.Swig({ autoescape: false }); // $ Alert
const tpl = swig.compile("<p>{{ name }}</p>", { autoescape: false }); // $ Alert

const options = { autoescape: false }; // $ Alert
swig.render("<p>{{ name }}</p>", options);

// Safe: escaping stays on.
swig.setDefaults({ autoescape: true, cache: false });
const safe = new swig.Swig({ cache: "memory" });
swig.compile("<p>{{ name }}</p>", { autoescape: "js" });
swig.setDefaults({ cache: false });

module.exports = { app, strict, tpl, safe };
