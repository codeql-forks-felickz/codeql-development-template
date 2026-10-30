const express = require('express');
const libxml = require('libxml');
const libxmljs2 = require('libxmljs2');
const libxmljs = require('libxmljs');

const router = express.Router();

router.post('/upload-products', (req, res) => {
  const XMLfile = req.files.products.data;
  // BAD: `libxml` expands external entities with `noent: true`
  const products = libxml.parseXmlString(XMLfile, { noent: true, noblanks: true });
  res.send(products.root().text());
});

router.post('/upload-products-2', (req, res) => {
  // BAD: `libxmljs2` expands external entities with `noent: true`
  libxmljs2.parseXml(req.body.xml, { noent: true });
  res.send('Thanks');
});

router.post('/upload-products-3', (req, res) => {
  // GOOD: entity expansion is not enabled
  libxml.parseXmlString(req.files.products.data, { noblanks: true });
  // GOOD: entity expansion is explicitly disabled
  libxmljs2.parseXmlString(req.body.xml, { noent: false });
  res.send('Thanks');
});

router.post('/upload-products-4', (req, res) => {
  // GOOD: constant input
  libxml.parseXmlString('<products/>', { noent: true });
  // Not reported here: `libxmljs` is already covered by the standard `js/xxe` query
  libxmljs.parseXmlString(req.body.xml, { noent: true });
  res.send('Thanks');
});

module.exports = router;
