import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

class JsonHeader {
    JsonHeader(String json) {}

    boolean has(String key) {
        return true;
    }

    String getString(String key) {
        return "";
    }
}

class JwtUtils {
    static final String JWT_ALGORITHM_KEY_HEADER = "alg";
    static final String NONE_ALGORITHM = "none";
    static final String PERIOD_REGEX = "\\.";
}

public class JwtValidators {

    boolean hmacValidator(String token, byte[] key) {
        return false;
    }

    // Mirrors the pattern from the issue: alg read via constants, lower-cased, contentEquals.
    public boolean noneAlgorithmVulnerableValidator(String token, byte[] key) {
        String[] parts = token.split(JwtUtils.PERIOD_REGEX, -1);
        JsonHeader header =
                new JsonHeader(
                        new String(
                                Base64.getUrlDecoder().decode(parts[0].getBytes(StandardCharsets.UTF_8)),
                                StandardCharsets.UTF_8));
        if (header.has(JwtUtils.JWT_ALGORITHM_KEY_HEADER)) {
            String alg = header.getString(JwtUtils.JWT_ALGORITHM_KEY_HEADER);
            if (JwtUtils.NONE_ALGORITHM.contentEquals(alg.toLowerCase())) { // $ Alert
                return true;
            }
        }
        return hmacValidator(token, key);
    }

    // Snippet from the issue description.
    public boolean mapHeaderEqualsIgnoreCase(Map<String, String> header) {
        String alg = header.get("alg");
        if ("none".equalsIgnoreCase(alg)) { return true; } // $ Alert
        return false;
    }

    public boolean mapHeaderEqualsReversed(Map<String, String> header) {
        if (header.get("alg").equals("NONE")) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean objectsEquals(Map<String, String> header) {
        String alg = header.get("alg");
        if (java.util.Objects.equals(alg, "none")) // $ Alert
            return true;
        return false;
    }

    // Safe: alg none is rejected.
    public boolean rejectsNone(Map<String, String> header, String token, byte[] key) {
        String alg = header.get("alg");
        if ("none".equalsIgnoreCase(alg)) {
            return false;
        }
        return hmacValidator(token, key);
    }

    // Safe: alg none results in an exception.
    public boolean throwsOnNone(Map<String, String> header, String token, byte[] key) {
        String alg = header.get("alg");
        if ("none".equalsIgnoreCase(alg)) {
            throw new IllegalArgumentException("alg none not allowed");
        }
        return hmacValidator(token, key);
    }

    // Safe: only returns true when alg is NOT none (and then the signature is checked).
    public boolean negatedGuard(Map<String, String> header, String token, byte[] key) {
        String alg = header.get("alg");
        if (!"none".equalsIgnoreCase(alg)) {
            return hmacValidator(token, key);
        }
        return false;
    }

    // Safe: comparison against a real algorithm.
    public boolean otherAlgorithm(Map<String, String> header, String token, byte[] key) {
        String alg = header.get("alg");
        if ("HS256".equals(alg)) {
            return true;
        }
        return false;
    }

    // Safe: value compared to none does not come from the alg header.
    public boolean notFromAlgHeader(Map<String, String> config) {
        String mode = config.get("mode");
        if ("none".equals(mode)) {
            return true;
        }
        return false;
    }

    // Safe: a configuration helper, with no JWT/header context.
    public boolean configuredAlgorithm(Map<String, String> config) {
        String alg = config.get("alg");
        if ("none".equals(alg)) return true;
        return false;
    }

    // A JWT parameter corroborates a generic map holding the decoded header.
    public boolean decodedAlgorithm(Map<String, String> data, String token) {
        String alg = data.get("alg");
        if ("none".equals(alg)) return true; // $ Alert
        return false;
    }

    // Safe: accepting none still requires verification to succeed.
    public boolean verifiesNoneBranch(Map<String, String> header, String token, byte[] key) {
        if ("none".equals(header.get("alg"))) {
            if (!hmacValidator(token, key)) return false;
            return true;
        }
        return false;
    }

    // A verification call whose result is ignored is not a guard.
    public boolean ignoresVerification(Map<String, String> header, String token, byte[] key) {
        if ("none".equals(header.get("alg"))) { // $ Alert
            hmacValidator(token, key);
            return true;
        }
        return false;
    }

    // An optional verification does not gate the successful return.
    public boolean optionallyVerifies(
            Map<String, String> header, String token, byte[] key, boolean verify) {
        if ("none".equals(header.get("alg"))) { // $ Alert
            if (verify) {
                if (!hmacValidator(token, key)) return false;
            }
            return true;
        }
        return false;
    }
}
