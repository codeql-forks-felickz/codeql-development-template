package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

public class JWT {
    public static JWTCreator.Builder create() { return null; }

    public static Verification require(Algorithm algorithm) { return null; }

    public static DecodedJWT decode(String token) { return null; }
}
