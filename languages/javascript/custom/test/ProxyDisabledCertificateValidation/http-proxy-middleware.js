import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';

const app = express();

app.use(
  '/api',
  createProxyMiddleware({
    target: 'https://backend.example.com',
    changeOrigin: true,
    secure: false // $ Alert
  })
);

app.use(
  '/safe',
  createProxyMiddleware({
    target: 'https://backend.example.com',
    changeOrigin: true
  })
);

app.listen(3000);
