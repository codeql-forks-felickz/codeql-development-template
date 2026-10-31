package com.nimbusds.jose.crypto;

import com.nimbusds.jose.JWSVerifier;
import java.security.interfaces.ECPublicKey;

public class ECDSAVerifier implements JWSVerifier {
    public ECDSAVerifier(ECPublicKey publicKey) {}
}
