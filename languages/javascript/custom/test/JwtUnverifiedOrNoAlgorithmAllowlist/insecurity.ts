import fs from "fs";
import expressJwt from "express-jwt";
import * as jwt from "jsonwebtoken";

const publicKey = fs ? fs.readFileSync("encryptionkeys/jwt.pub", "utf8") : "placeholder-public-key";

// BAD: public key without an algorithm allowlist
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any); // $ Alert

// GOOD: algorithm allowlist
export const isAuthorizedSafe = () => expressJwt(({ secret: publicKey, algorithms: ["RS256"] }) as any);

export const verify = (token: string) => jwt.verify(token, publicKey, { algorithms: ["RS256"] });
