import { type Request, type Response } from 'express'
import * as security from './insecurity'

// Reduced from a "whoami" endpoint: authenticated profile data returned as JSONP.
export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let response: any
    if (security.verify(req.cookies.token)) {
      const user = security.authenticatedUsers.get(req.cookies.token)
      response = { user: { id: user?.data?.id, email: user?.data?.email } }
    } else {
      response = { user: {} }
    }
    if (req.query.callback === undefined) {
      res.json(response) // OK: plain JSON is not readable cross-origin
    } else {
      res.jsonp(response) // $ Alert
    }
  }
}
