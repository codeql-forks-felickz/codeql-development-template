package com.auth0.jwt.interfaces;

public interface DecodedJWT extends Payload, Header {
  String getToken();
}
