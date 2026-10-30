import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

class Header {
    Header(String json) {}

    boolean has(String key) { return true; }

    String getString(String key) { return ""; }
}

class Utils {
    static final char PERIOD = '.';
    static final String PERIOD_REGEX = "[" + PERIOD + "]";
    static final String ALG = "alg";
}

public class EmptyTokenValidators {
    boolean hmacValidator(String token, byte[] key) { return false; }

    Header decode(String part) {
        return new Header(new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8));
    }

    // Mirrors the VulnerableApp pattern: a token such as "." or "..." splits into zero parts.
    public boolean emptyTokenValidator(String token, byte[] key) {
        String[] jwtParts = token.split(Utils.PERIOD_REGEX);
        if (jwtParts.length == 0) { // $ Alert
            return true;
        } else {
            Header header = decode(jwtParts[0]);
            if (header.has(Utils.ALG)) {
                String alg = header.getString(Utils.ALG);
                if (alg.startsWith("HS")) {
                    return hmacValidator(token, key);
                }
            }
            return false;
        }
    }

    // Variant: `< 1` and a JWT-named parameter, no alg read.
    public boolean lessThanOne(String jwt, byte[] key) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 1) return true; // $ Alert
        return hmacValidator(jwt, key);
    }

    // Variant: negated check with the valid result in the else branch.
    public boolean notEqualElse(String token, byte[] key) {
        String[] parts = token.split("\\.");
        if (parts.length != 0) { // $ Alert
            return hmacValidator(token, key);
        } else {
            return true;
        }
    }

    // Safe: empty tokens are rejected.
    public boolean rejectsEmpty(String token, byte[] key) {
        String[] parts = token.split("\\.");
        if (parts.length == 0) {
            return false;
        }
        return hmacValidator(token, key);
    }

    // Safe: requires all three parts before verifying.
    public boolean requiresThreeParts(String token, byte[] key) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        return hmacValidator(token, key);
    }

    // Safe: not a JWT (comma separated list, no JWT context).
    public boolean isEmptyList(String csv) {
        String[] items = csv.split(",");
        if (items.length == 0) {
            return true;
        }
        return false;
    }

    // Explicit zero also discards trailing empty parts.
    public boolean explicitZeroLimit(String token) {
        final int limit = 0;
        String[] parts = token.split("\\.", limit);
        if (parts.length == 0) return true; // $ Alert
        return false;
    }

    // Safe: a negative limit retains empty parts, so zero length is unreachable.
    public boolean negativeLimit(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length == 0) return true;
        return false;
    }

    // Safe: a positive limit also retains a final empty part.
    public boolean positiveLimit(String token) {
        String[] parts = token.split("\\.", 2);
        if (parts.length == 0) return true;
        return false;
    }

    // Safe: success in the empty branch still requires signature verification.
    public boolean verifiesEmptyBranch(String token, byte[] key) {
        String[] parts = token.split("\\.");
        if (parts.length == 0) {
            if (!hmacValidator(token, key)) return false;
            return true;
        }
        return false;
    }

    // Ignoring a verification result must not suppress the unverified acceptance.
    public boolean ignoresVerification(String token, byte[] key) {
        String[] parts = token.split("\\.");
        if (parts.length == 0) { // $ Alert
            hmacValidator(token, key);
            return true;
        }
        return false;
    }

    // Verification on only an optional path does not gate the successful return.
    public boolean optionallyVerifies(String token, byte[] key, boolean verify) {
        String[] parts = token.split("\\.");
        if (parts.length == 0) { // $ Alert
            if (verify) {
                if (!hmacValidator(token, key)) return false;
            }
            return true;
        }
        return false;
    }
}
