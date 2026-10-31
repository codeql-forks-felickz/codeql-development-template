package com.auth0.jwt.interfaces;

import com.auth0.jwt.JWTVerifier;

public interface Verification {
    JWTVerifier build();
}
