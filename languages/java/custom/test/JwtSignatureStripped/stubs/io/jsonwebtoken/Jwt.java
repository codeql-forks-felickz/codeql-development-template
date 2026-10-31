package io.jsonwebtoken;

public interface Jwt<H extends Header, B> {
    B getBody();
}
