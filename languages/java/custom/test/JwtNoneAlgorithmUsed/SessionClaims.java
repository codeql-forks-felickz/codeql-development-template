import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import javax.servlet.http.HttpSession;

public class SessionClaims {
    public String accept(String token, HttpSession session, org.springframework.ui.Model model) {
        DecodedJWT decoded = JWT.decode(token);
        String username = decoded.getClaim("username").asString();
        if (username.equalsIgnoreCase((String) session.getAttribute("username"))) { // $ Alert
            model.addAttribute("isValidMessage", "Token is valid for your username!");
        }
        return "token";
    }

    public boolean aliases(String token, HttpSession session) {
        DecodedJWT decoded = JWT.decode(token);
        DecodedJWT alias = decoded;
        Claim claim = alias.getClaim("username");
        Claim claimAlias = claim;
        String username = claimAlias.asString();
        String nameAlias = username;
        String sessionName = (String) session.getAttribute("username");
        if (sessionName.equals(nameAlias)) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean differentToken(String token, String other, HttpSession session, JWTVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        verifier.verify(other);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean tooLate(String token, HttpSession session, JWTVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        verifier.verify(decoded);
        return false;
    }

    public boolean conditionalVerification(String token, HttpSession session, JWTVerifier verifier, boolean check) {
        DecodedJWT decoded = JWT.decode(token);
        if (check) verifier.verify(decoded);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public void logged(String token) {
        System.out.println(JWT.decode(token).getClaim("username").asString());
    }

    public boolean verified(String token, HttpSession session, String secret) {
        DecodedJWT decoded = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            return true;
        }
        return false;
    }

    public boolean verifiedBeforeDecode(String token, HttpSession session, com.auth0.jwt.JWTVerifier verifier) {
        String alias = token;
        verifier.verify(alias);
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            return true;
        }
        return false;
    }

    public boolean verifiedDecoded(String token, HttpSession session, JWTVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        DecodedJWT alias = decoded;
        verifier.verify(alias);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            return true;
        }
        return false;
    }

    public boolean verifiedAlgorithm(String token, HttpSession session, Algorithm algorithm) {
        DecodedJWT decoded = JWT.decode(token);
        DecodedJWT alias = decoded;
        algorithm.verify(alias);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            return true;
        }
        return false;
    }

    public boolean differentKey(String token, HttpSession session) {
        if (JWT.decode(token).getClaim("username").asString().equals(session.getAttribute("role"))) {
            return true;
        }
        return false;
    }

    public boolean mapRead(String token, java.util.Map<String, String> values) {
        if (JWT.decode(token).getClaim("username").asString().equals(values.get("username"))) {
            return true;
        }
        return false;
    }

    public void unusedComparison(String token, HttpSession session) {
        boolean equal = JWT.decode(token).getClaim("username").asString().equals(session.getAttribute("username"));
        System.out.println(equal);
    }

    public boolean unrelatedVerifier(String token, HttpSession session, OtherVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        verifier.verify(decoded);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean ignoredVerificationFailure(String token, HttpSession session, JWTVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        try {
            verifier.verify(decoded);
        } catch (RuntimeException ignored) {
        }
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public interface OtherVerifier {
        void verify(DecodedJWT jwt);
    }

    public boolean noneAlgorithmVerification(String token, HttpSession session) {
        DecodedJWT decoded = JWT.decode(token);
        Algorithm algorithm = Algorithm.none();
        algorithm.verify(decoded);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean noneVerifier(String token, HttpSession session) {
        Algorithm algorithm = Algorithm.none();
        com.auth0.jwt.interfaces.Verification builder = JWT.require(algorithm); // $ Alert
        JWTVerifier verifier = builder.build();
        verifier.verify(token);
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            return true;
        }
        return false;
    }

    public boolean hmacAlgorithmVerification(String token, HttpSession session, String secret) {
        DecodedJWT decoded = JWT.decode(token);
        Algorithm algorithm = Algorithm.HMAC256(secret);
        algorithm.verify(decoded);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            return true;
        }
        return false;
    }

    public boolean verifiedInsideMatchingBranch(String token, HttpSession session, JWTVerifier verifier) {
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            DecodedJWT alias = decoded;
            verifier.verify(alias);
            return true;
        }
        return false;
    }

    public String verificationBeforeModelTrust(String token, HttpSession session, JWTVerifier verifier, org.springframework.ui.Model model) {
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            verifier.verify(decoded);
            model.addAttribute("isValidMessage", "Token is valid for your username!");
        }
        return "token";
    }

    public String verificationAfterModelTrust(String token, HttpSession session, JWTVerifier verifier, org.springframework.ui.Model model) {
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) { // $ Alert
            model.addAttribute("isValidMessage", "Token is valid for your username!");
            verifier.verify(decoded);
        }
        return "token";
    }

    public void comparisonOnlyLogged(String token, HttpSession session) {
        DecodedJWT decoded = JWT.decode(token);
        if (decoded.getClaim("username").asString().equals(session.getAttribute("username"))) {
            System.out.println("Matching username");
        }
    }
}
