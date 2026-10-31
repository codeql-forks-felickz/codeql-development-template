const nunjucks = require("nunjucks");
const Handlebars = require("handlebars");

nunjucks.configure("views", { autoescape: false }); // $ Alert
nunjucks.configure({ autoescape: false, watch: true }); // $ Alert
const env = new nunjucks.Environment(new nunjucks.FileSystemLoader("views"), { autoescape: false }); // $ Alert

const unsafe = Handlebars.compile("<p>{{name}}</p>", { noEscape: true }); // $ Alert

// Safe: escaping stays on.
nunjucks.configure("views", { autoescape: true });
nunjucks.configure("views");
const safeEnv = new nunjucks.Environment(new nunjucks.FileSystemLoader("views"));
const safe = Handlebars.compile("<p>{{name}}</p>", { noEscape: false, strict: true });

module.exports = { env, unsafe, safeEnv, safe };
