package com.nimbusds.jose.crypto;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPublicKey;

public class RSASSAVerifier implements JWSVerifier {
    public RSASSAVerifier(RSAPublicKey publicKey) {}

    public RSASSAVerifier(RSAKey rsaPublicKey) {}
}
