package com.auth0.jwt.interfaces;

public interface Payload {
  String getIssuer();

  Claim getClaim(String name);
}
