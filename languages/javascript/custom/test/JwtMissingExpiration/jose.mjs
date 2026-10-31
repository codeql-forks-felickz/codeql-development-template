import { SignJWT } from "jose";
import * as jose from "jose";

export async function chainedWithoutExpiry(sub, key) {
  return await new SignJWT({ sub }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().sign(key); // $ Alert
}

export async function namespaceWithoutExpiry(sub, key) {
  return await new jose.SignJWT({ sub, role: "user" }).setProtectedHeader({ alg: "ES256" }).sign(key); // $ Alert
}

export async function stepwiseWithoutExpiry(sub, key) {
  const builder = new SignJWT({ sub });
  builder.setProtectedHeader({ alg: "HS256" });
  builder.setIssuedAt();
  return builder.sign(key); // $ Alert
}

// SAFE: setExpirationTime in the chain.
export async function chainedWithExpiry(sub, key) {
  return await new SignJWT({ sub })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(key);
}

// SAFE: setExpirationTime on the builder variable.
export async function stepwiseWithExpiry(sub, key) {
  const builder = new SignJWT({ sub });
  builder.setProtectedHeader({ alg: "HS256" });
  builder.setExpirationTime("15m");
  return builder.sign(key);
}

// SAFE: `exp` claim in the payload.
export async function expClaim(sub, key) {
  return await new SignJWT({ sub, exp: Math.floor(Date.now() / 1000) + 600 })
    .setProtectedHeader({ alg: "HS256" })
    .sign(key);
}

function configure(builder) {
  builder.setExpirationTime("1h");
}

// SAFE: builder escapes to a helper that may set the expiration.
export async function helperConfigured(sub, key) {
  const builder = new SignJWT({ sub }).setProtectedHeader({ alg: "HS256" });
  configure(builder);
  return builder.sign(key);
}
