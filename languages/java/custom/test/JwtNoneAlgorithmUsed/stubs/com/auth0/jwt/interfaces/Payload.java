package com.auth0.jwt.interfaces;

public interface Payload {
    Claim getClaim(String name);
}
