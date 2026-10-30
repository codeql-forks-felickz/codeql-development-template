package io.jsonwebtoken;

public interface JwtParser {
    JwtParser setSigningKey(byte[] key);

    Jwt parse(String jwt);

    Jwt<Header, Claims> parseClaimsJwt(String claimsJwt);

    Jwt<Header, String> parsePlaintextJwt(String plaintextJwt);

    Jws<Claims> parseClaimsJws(String claimsJws);

    Jwt<Header, Claims> parseUnsecuredClaims(String claimsJwt);

    Jwt<Header, byte[]> parseUnsecuredContent(String contentJwt);
}
