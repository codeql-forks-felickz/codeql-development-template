import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

public class TokenDecoder {

    // Mirrors the unguard pattern: the signature part is dropped before an unsigned parse.
    public static Claims decodeTokenClaims(String token) {
        String[] splitToken = token.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        Jwt<Header, Claims> untrusted = Jwts.parser().parseClaimsJwt(unsignedToken); // $ Alert
        return untrusted.getBody();
    }

    // Variant: signature removed with substring/lastIndexOf, inline argument.
    public static Claims substringStrip(String token) {
        return Jwts.parser().parseClaimsJwt(token.substring(0, token.lastIndexOf('.') + 1)).getBody(); // $ Alert
    }

    // Variant: plaintext parse even when a key is configured.
    public static String plaintext(String token, byte[] key) {
        String[] parts = token.split("\\.");
        return Jwts.parser().setSigningKey(key).parsePlaintextJwt(parts[0] + "." + parts[1] + ".").getBody(); // $ Alert
    }

    // Safe: the full signed token is verified.
    public static Claims verified(String token, byte[] key) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
    }

    // Safe: the signature part is kept.
    public static Claims keepsSignature(String token) {
        String[] p = token.split("\\.");
        return Jwts.parser().parseClaimsJwt(p[0] + "." + p[1] + "." + p[2]).getBody();
    }

    // Safe: stripped token is only logged, not parsed.
    public static void logOnly(String token) {
        String[] p = token.split("\\.");
        System.out.println(p[0] + "." + p[1] + ".");
    }
}
