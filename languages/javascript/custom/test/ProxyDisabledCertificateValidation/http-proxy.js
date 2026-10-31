import httpProxy from 'http-proxy';
import http from 'http';

const insecure = httpProxy.createProxyServer({
  target: 'https://backend.example.com',
  secure: false // $ Alert
});

const safe = httpProxy.createProxyServer({
  target: 'https://backend.example.com',
  secure: true
});

const server = httpProxy.createServer({ target: 'https://backend.example.com' });

http.createServer((req, res) => {
  server.web(req, res, {
    target: 'https://other.example.com',
    secure: false // $ Alert
  });
  safe.web(req, res, { target: 'https://other.example.com' });
  insecure.web(req, res);
});

// Unrelated object with a `secure` property is not a proxy option.
const cookieOptions = { secure: false };
export { cookieOptions };
