package com.auth0.jwt.interfaces;

public interface Header {
  String getKeyId();

  Claim getHeaderClaim(String name);
}
