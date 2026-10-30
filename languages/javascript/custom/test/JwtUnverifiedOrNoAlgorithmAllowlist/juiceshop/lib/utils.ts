export const jwtFrom = ({ headers }: { headers: any }) => {
  if (headers?.authorization) {
    const parts = headers.authorization.split(' ')
    if (parts.length === 2) {
      const scheme = parts[0]
      const token = parts[1]
      if (/^Bearer$/i.test(scheme)) {
        return token
      }
    }
  }
  return undefined
}
