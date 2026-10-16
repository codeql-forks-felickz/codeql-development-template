import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class TokenService {
    private static final Algorithm NONE_ALG = Algorithm.none();

    // Mirrors the vuln-spring pattern: tokens are issued without a signature.
    public String issueUnsigned(String username) {
        Algorithm algorithmNone = Algorithm.none();
        return JWT.create().withIssuer("app").withClaim("username", username).sign(algorithmNone); // $ Alert
    }

    // A verifier that requires the none algorithm accepts unsigned tokens.
    public JWT.Verification verifierAcceptsNone() {
        return JWT.require(Algorithm.none()); // $ Alert
    }

    // Through a static field.
    public String issueWithField(String username) {
        return JWT.create().withClaim("username", username).sign(NONE_ALG); // $ Alert
    }

    // Safe: HMAC-signed token.
    public String issueSigned(String username, String secret) {
        return JWT.create().withClaim("username", username).sign(Algorithm.HMAC256(secret));
    }

    // Safe: Algorithm.none() created but never used to sign or verify.
    public Algorithm unused() {
        return Algorithm.none();
    }
}
