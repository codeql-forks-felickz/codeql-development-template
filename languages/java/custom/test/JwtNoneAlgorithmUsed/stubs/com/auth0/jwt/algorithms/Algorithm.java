package com.auth0.jwt.algorithms;

public abstract class Algorithm {
    public static Algorithm none() { return null; }

    public static Algorithm HMAC256(String secret) { return null; }
}
