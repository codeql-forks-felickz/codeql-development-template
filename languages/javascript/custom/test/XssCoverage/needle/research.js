const express = require("express");
const needle = require("needle");

const app = express();

// The attacker controls the URL that is fetched, and therefore the response body.
app.get("/research", (req, res) => {
  const url = req.query.url + req.query.symbol; // $ Source[js/reflected-xss-via-fetched-url]
  return needle.get(url, (error, newResponse, body) => {
    if (!error && newResponse.statusCode === 200) {
      res.writeHead(200, { "Content-Type": "text/html" });
    }
    res.write("<h1>The following is the stock information you requested.</h1>\n\n");
    if (body) {
      res.write(body); // $ Alert[js/reflected-xss-via-fetched-url]
    }
    return res.end();
  });
});

app.get("/research-resp-body", (req, res) => {
  needle.get(req.query.url, { follow_max: 2 }, (error, response) => { // $ Source[js/reflected-xss-via-fetched-url]
    res.send(response.body); // $ Alert[js/reflected-xss-via-fetched-url]
  });
});

app.get("/research-request", (req, res) => {
  needle.request("get", req.query.url, null, (error, response, body) => { // $ Source[js/reflected-xss-via-fetched-url]
    res.send(body); // $ Alert[js/reflected-xss-via-fetched-url]
  });
});

app.get("/research-promise", async (req, res) => {
  const response = await needle("get", req.query.url); // $ Source[js/reflected-xss-via-fetched-url]
  res.send(response.body); // $ Alert[js/reflected-xss-via-fetched-url]
});

// Safe: the URL is a constant, so the response is not attacker-controlled.
app.get("/fixed", (req, res) => {
  needle.get("https://stocks.example.com/quote", (error, response, body) => {
    res.send(body);
  });
});

// Safe: the attacker-controlled URL is fetched, but the body is never written to the response.
app.get("/status", (req, res) => {
  needle.get(req.query.url, (error, response, body) => {
    res.send(String(response.statusCode));
  });
});

// Safe: the scheme and host are fixed; the user only controls a query parameter.
app.get("/quote", (req, res) => {
  needle.get("https://stocks.example.com/quote?symbol=" + req.query.symbol, (error, response, body) => {
    res.send(body);
  });
});

// Safe: the origin comes from configuration; the user only controls the path.
app.get("/config-origin", (req, res) => {
  needle.get(process.env.STOCKS_API + "/quote/" + req.query.symbol, (error, response, body) => {
    res.send(body);
  });
});

// Safe: the response is HTML-escaped before being written.
app.get("/escaped", (req, res) => {
  needle.get(req.query.url, (error, response, body) => {
    res.send(escape(body));
  });
});

function escape(s) {
  return String(s).replace(/[&<>"']/g, (c) => "&#" + c.charCodeAt(0) + ";");
}

// Other HTTP clients are covered too.
const axios = require("axios");
app.get("/axios", async (req, res) => {
  const response = await axios.get(req.query.url); // $ Source[js/reflected-xss-via-fetched-url]
  res.send(response.data); // $ Alert[js/reflected-xss-via-fetched-url]
});

app.listen(3000);
