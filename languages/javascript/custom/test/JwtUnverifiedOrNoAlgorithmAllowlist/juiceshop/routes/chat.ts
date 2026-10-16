import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import { roles } from '../lib/insecurity'
import * as utils from '../lib/utils'

export async function getUserId (req: Request): Promise<number | undefined> {
  const token = utils.jwtFrom(req)
  if (!token) return undefined
  // BAD: identity taken from a token whose signature is never verified
  const decoded = security.decode(token) as { data?: { id?: number } } | undefined // $ Alert
  return decoded?.data?.id
}

export function chat () {
  return async (req: Request, res: Response) => {
    const userId = await getUserId(req)
    const token = utils.jwtFrom(req)
    // BAD: role taken from a token whose signature is never verified
    const decoded = token ? security.decode(token) as { data?: { role?: string } } : undefined // $ Alert
    const isAdmin = decoded?.data?.role === roles.admin
    res.json({ userId, isAdmin })
  }
}
