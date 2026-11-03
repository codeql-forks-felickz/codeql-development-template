// Reduced from a juice-shop-style application: all proxies are trusted and the
// reset-password limiter is keyed on `headers['X-Forwarded-For'] ?? ip`. Node.js lower-cases
// header names, so the header read is always undefined and the key is `req.ip`, which is
// taken from the client-supplied `X-Forwarded-For` header because all proxies are trusted.
import express from 'express'
import { rateLimit } from 'express-rate-limit'

const app = express()

export async function start () {
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] ?? ip } // $ Alert
  }))

  // GOOD: the limiter is keyed on the authenticated user rather than on the client address.
  app.use('/rest/user/change-password', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator: (req: any) => req.user.id
  }))

  // A sub-router of the application inherits its `trust proxy` setting.
  const api = express.Router()
  api.post('/2fa/verify', rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    keyGenerator: (req: any) => req.ips[0] // $ Alert
  }), (req: any, res: any) => res.end())
  app.use('/api', api)
}
