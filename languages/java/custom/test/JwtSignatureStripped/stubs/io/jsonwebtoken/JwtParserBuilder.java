package io.jsonwebtoken;

public interface JwtParserBuilder {
    JwtParserBuilder unsecured();

    JwtParserBuilder setSigningKey(byte[] key);

    JwtParser build();
}
