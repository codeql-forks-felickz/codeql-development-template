package com.auth0.jwt.interfaces;

public interface JWTVerifier {
    DecodedJWT verify(String token);
    DecodedJWT verify(DecodedJWT jwt);
}
