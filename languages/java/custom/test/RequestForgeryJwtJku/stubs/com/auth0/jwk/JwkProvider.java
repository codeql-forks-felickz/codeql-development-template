package com.auth0.jwk;

public interface JwkProvider {
  Object get(String keyId);
}
