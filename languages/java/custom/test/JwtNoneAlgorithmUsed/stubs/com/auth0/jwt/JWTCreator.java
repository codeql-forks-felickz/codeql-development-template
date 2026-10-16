package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public final class JWTCreator {
    public static class Builder {
        public Builder withIssuer(String issuer) { return this; }

        public Builder withClaim(String name, String value) { return this; }

        public String sign(Algorithm algorithm) { return null; }
    }
}
