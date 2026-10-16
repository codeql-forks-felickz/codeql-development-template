import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.json.JSONObject;

public class JwkValidators {
    static final String JWT_ALGORITHM_KEY_HEADER = "alg";
    static final String JSON_WEB_KEY_HEADER = "jwk";

    JSONObject decodeHeader(String token) {
        String[] parts = token.split("\\.", -1);
        return new JSONObject(
                new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
    }

    // Mirrors the VulnerableApp pattern: key material is taken from the token's own jwk header.
    public JWSVerifier jwkHeaderTrusted(String token) throws Exception {
        JSONObject header = decodeHeader(token);
        String alg = header.getString(JWT_ALGORITHM_KEY_HEADER);
        JWSVerifier verifier = null;
        if (header.has(JSON_WEB_KEY_HEADER)) {
            if (alg.startsWith("RS")) {
                RSAKey rsaKey = RSAKey.parse(header.getJSONObject(JSON_WEB_KEY_HEADER).toString());
                verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey()); // $ Alert
            } else if (alg.startsWith("ES")) {
                ECKey ecKey = ECKey.parse(header.getJSONObject("jwk").toString());
                verifier = new ECDSAVerifier(ecKey.toECPublicKey()); // $ Alert
            }
        }
        return verifier;
    }

    // Nimbus header API: the embedded JWK is attacker-controlled.
    public JWSVerifier nimbusHeaderJwk(JWSHeader header) throws Exception {
        return new RSASSAVerifier(header.getJWK().toRSAKey()); // $ Alert
    }

    // Safe: the key comes from server-side configuration, not the token.
    public JWSVerifier serverKey(Map<String, String> config) throws Exception {
        RSAKey rsaKey = RSAKey.parse(config.get("jwk"));
        return new RSASSAVerifier(rsaKey.toRSAPublicKey());
    }

    // Safe: the jwk header is only read for logging, the verifier uses a trusted key.
    public JWSVerifier jwkOnlyLogged(String token, RSAKey trusted) throws Exception {
        JSONObject header = decodeHeader(token);
        if (header.getString("alg") != null) {
            System.out.println(header.getJSONObject("jwk"));
        }
        return new RSASSAVerifier(trusted.toRSAPublicKey());
    }
}
