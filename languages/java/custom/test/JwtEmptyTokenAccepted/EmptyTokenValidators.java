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
}
