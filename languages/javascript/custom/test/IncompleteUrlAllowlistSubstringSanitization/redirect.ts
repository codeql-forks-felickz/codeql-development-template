import * as express from 'express'

export const redirectAllowlist = new Set([
  'https://github.com/example-org/example-app', // $ RelatedLocation
  'https://shop.example.com/products/42',
  'http://docs.example.org/guide'
])

// BAD: the target only has to contain an allowlisted URL somewhere
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // $ Alert
  }
  return allowed
}

const trustedOrigins = ['https://partner.example.com', 'https://cdn.example.net'] // $ RelatedLocation

// BAD: same weakness through an array callback
export function isTrustedArray (url: string): boolean {
  return trustedOrigins.some(origin => url.indexOf(origin) !== -1) // $ Alert
}

// BAD: prefix check without a trailing slash, `https://partner.example.com.evil.net` passes
export function startsWithTrusted (url: string): boolean {
  return trustedOrigins.some(origin => url.startsWith(origin)) // $ Alert
}

const trustedPrefixes = ['https://partner.example.com/', 'https://cdn.example.net/']

// GOOD: prefix check including the trailing slash
export function startsWithTrustedSlash (url: string): boolean {
  return trustedPrefixes.some(prefix => url.startsWith(prefix))
}

// GOOD: exact match against the allowlist
export const isRedirectAllowedExact = (url: string) => redirectAllowlist.has(url)

// GOOD: exact comparison inside the loop
export const isRedirectAllowedLoopExact = (url: string) => {
  for (const allowedUrl of redirectAllowlist) {
    if (url === allowedUrl) return true
  }
  return false
}

// GOOD: a reused `var` belongs to the second loop's safe allowlist
export function reusesVarAcrossLoops (url: string): boolean {
  for (var prefix of ['https://partner.example.com']) {}
  for (var prefix of ['https://partner.example.com/']) {
    return url.startsWith(prefix)
  }
  return false
}

const fileExtensions = ['.png', '.jpg', '.gif']

// GOOD: substring checks against values that are not URLs
export function isImage (name: string): boolean {
  return fileExtensions.some(ext => name.includes(ext))
}

// Already reported by the standard query, so not reported again here
export function constantCheck (url: string): boolean {
  return url.includes('https://github.com/example-org/example-app')
}

const app = express()
app.get('/redirect', (req, res) => {
  const toUrl = req.query.to as string
  if (isRedirectAllowed(toUrl)) {
    res.redirect(toUrl)
  } else {
    res.status(406).send('Unrecognized target URL for redirect')
  }
})
