import fs from 'fs'
import jws from 'jws'
import { type Request, type Response, type NextFunction } from 'express'
import * as utils from './utils'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'

// BAD: `jws.verify(signature, key)` trusts the algorithm in the token header
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false // $ Alert
// Wrapper around an unverified decode: reported at the call sites that use it without verification
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const roles = { customer: 'customer', admin: 'admin', accounting: 'accounting' }

// GOOD: the token is verified before it is decoded
export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

// GOOD: the token is verified before it is decoded
export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}
