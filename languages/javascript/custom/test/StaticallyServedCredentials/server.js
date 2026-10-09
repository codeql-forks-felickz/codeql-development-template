var express = require('express');
var serveStatic = require('serve-static');
var path = require('path');
var Koa = require('koa');
var koaStatic = require('koa-static');

var app = express();

// Relative to the working directory (the folder containing package.json).
app.use(express.static("public"));

// Same folder, resolved from __dirname (as in the original report).
app.use(serveStatic(__dirname + '/public'));

app.use(serveStatic(__dirname + '/assets/'));

app.use("/static", express.static(path.join(__dirname, "static")));

var wwwDir = "./www";
app.use(serveStatic(wwwDir));

var koa = new Koa();
koa.use(koaStatic(path.resolve(__dirname, 'koa-public')));

// Not served: `private` is never passed to a static-file middleware.
var config = require('./private/creds.json');

app.listen(8080);
