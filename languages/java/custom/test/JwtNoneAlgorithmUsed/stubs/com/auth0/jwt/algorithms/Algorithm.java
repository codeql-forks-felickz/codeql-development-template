package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.DecodedJWT;

public abstract class Algorithm {
    public static Algorithm none() { return null; }

    public static Algorithm HMAC256(String secret) { return null; }

    public abstract void verify(DecodedJWT jwt);
}
