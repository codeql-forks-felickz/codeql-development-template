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

// Safe: a helper fetches a fixed origin; only the query is user-controlled.
app.get("/helper-fixed-origin", (req, res) => {
  fetchAndSend("https://stocks.example.com/quote?symbol=" + req.query.symbol, res);
});

// The helper must still report when the user controls the origin.
app.get("/helper-tainted-origin", (req, res) => {
  fetchAndSend("https://" + req.query.host + "/", res); // $ Source[js/reflected-xss-via-fetched-url]
});

function fetchAndSend(url, res) {
  needle.get(url, (error, response, body) => {
    res.send(body); // $ Alert[js/reflected-xss-via-fetched-url]
  });
}

// The fixed scheme does not make a user-controlled host safe.
app.get("/fixed-scheme-tainted-host", (req, res) => {
  needle.get("https://" + req.query.host + "/", (error, response, body) => { // $ Source[js/reflected-xss-via-fetched-url]
    res.send(body); // $ Alert[js/reflected-xss-via-fetched-url]
  });
});

// Safe: the origin comes from configuration; the user only controls the path.
app.get("/config-origin", (req, res) => {
  needle.get(process.env.STOCKS_API + "/quote/" + req.query.symbol, (error, response, body) => {
    res.send(body);
  });
});

// Safe: an exact origin check constrains the requested host.
app.get("/validated-origin", (req, res) => {
  const url = req.query.url;
  if (new URL(url).origin === "https://stocks.example.com") {
    needle.get(url, (error, response, body) => {
      res.send(body);
    });
  }
});

// Safe: an exact host check constrains the requested host.
app.get("/validated-host", (req, res) => {
  const url = req.query.url;
  if (new URL(url).host === "stocks.example.com") {
    needle.get(url, (error, response, body) => {
      res.send(body);
    });
  }
});

// Safe: the parsed origin must match one of the fixed allow-list entries.
app.get("/validated-origin-allow-list", (req, res) => {
  const url = req.query.url;
  if (["https://stocks.example.com"].includes(new URL(url).origin)) {
    needle.get(url, (error, response, body) => {
      res.send(body);
    });
  }
});

// Unsafe: a prefix without a slash does not delimit the host.
app.get("/unsound-prefix", (req, res) => {
  const url = req.query.url; // $ Source[js/reflected-xss-via-fetched-url]
  if (url.startsWith("https://stocks.example.com")) {
    needle.get(url, (error, response, body) => {
      res.send(body); // $ Alert[js/reflected-xss-via-fetched-url]
    });
  }
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

app.get("/axios-response-fields", async (req, res) => {
  const response = await axios.get(req.query.url); // $ Source[js/reflected-xss-via-fetched-url]
  res.send(response.data.status); // $ Alert[js/reflected-xss-via-fetched-url]
  res.send(response.headers["x-message"]); // $ Alert[js/reflected-xss-via-fetched-url]
});

app.listen(3000);
