package com.auth0.jwk;

import java.net.URL;

public class UrlJwkProvider implements JwkProvider {
  public UrlJwkProvider(URL url) {}

  public UrlJwkProvider(String domain) {}

  public Object get(String keyId) {
    return null;
  }
}
