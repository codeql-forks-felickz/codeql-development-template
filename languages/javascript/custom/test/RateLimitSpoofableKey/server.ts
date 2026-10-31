// Reduced from a juice-shop-style application: all proxies are trusted and the
// reset-password limiter is keyed on the raw `X-Forwarded-For` header, falling back to `req.ip`.
import express from 'express'
import { rateLimit } from 'express-rate-limit'

const app = express()

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
