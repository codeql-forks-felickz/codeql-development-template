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

    // Finding 6: modern parsers reject unsecured tokens unless explicitly enabled.
    public static void modernDefaults(String token) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        Jwts.parserBuilder().build().parseUnsecuredClaims(unsigned);
        Jwts.parserBuilder().build().parseUnsecuredContent(unsigned);
    }

    public static void modernUnsecuredChain(String token) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        Jwts.parserBuilder().unsecured().build().parseUnsecuredClaims(unsigned); // $ Alert
        Jwts.parserBuilder().unsecured().build().parseUnsecuredContent(unsigned); // $ Alert
    }

    public static void modernUnsecuredLocal(String token, byte[] key) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        io.jsonwebtoken.JwtParserBuilder builder = Jwts.parserBuilder();
        builder.unsecured();
        io.jsonwebtoken.JwtParser parser = builder.setSigningKey(key).build();
        parser.parseUnsecuredClaims(unsigned); // $ Alert
        parser.parseUnsecuredContent(unsigned); // $ Alert
        Jwts.parserBuilder().build().parseUnsecuredClaims(unsigned);
    }

    // The JJWT 0.11 generic API does not require the modern builder option.
    public static void legacyGeneric(String token, byte[] key) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        Jwts.parser().parse(unsigned); // $ Alert
        Jwts.parser().setSigningKey(key).parse(unsigned); // $ Alert
    }

    // Finding 7: retaining a signature through a local alias is not stripping it.
    public static void signatureAlias(String token, byte[] key) {
        String[] p = token.split("\\.");
        String sig = p[2];
        Jwts.parser().setSigningKey(key).parse(p[0] + "." + p[1] + "." + sig);
    }

    public static void laterPartAlias(String token, byte[] key) {
        String[] p = token.split("\\.");
        String suffix = p[3];
        Jwts.parser().setSigningKey(key).parse(p[0] + "." + p[1] + "." + suffix);
    }

    public static void strippedDirectConcat(String token, byte[] key) {
        String[] p = token.split("\\.");
        Jwts.parser().setSigningKey(key).parse(p[0] + "." + p[1] + "."); // $ Alert
    }

    // Finding 8: only a period on the same token marks the signature boundary.
    public static void substringOtherDelimiter(String token, byte[] key) {
        Jwts.parser().setSigningKey(key).parse(token.substring(0, token.lastIndexOf(' ')));
    }

    public static void substringOtherToken(String token, String other, byte[] key) {
        Jwts.parser().setSigningKey(key).parse(token.substring(0, other.lastIndexOf('.')));
    }

    public static void substringPeriods(String token, byte[] key) {
        Jwts.parser().setSigningKey(key).parse(token.substring(0, token.lastIndexOf('.'))); // $ Alert
        Jwts.parser().setSigningKey(key).parse(token.substring(0, token.lastIndexOf("."))); // $ Alert
        Jwts.parser().setSigningKey(key).parse(token.substring(0, token.lastIndexOf(".") + 1)); // $ Alert
    }

    // Finding 9: taint through rebuilding is not value-preserving flow of a stripped JWT.
    public static void signatureRestored(String token, byte[] key) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        String rebuilt = unsigned + p[2];
        Jwts.parser().setSigningKey(key).parse(rebuilt);
    }

    public static void strippedLocalAlias(String token, byte[] key) {
        String[] p = token.split("\\.");
        String unsigned = p[0] + "." + p[1] + ".";
        String alias = unsigned;
        Jwts.parser().setSigningKey(key).parse(alias); // $ Alert
    }
}
