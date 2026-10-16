import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.net.URL;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// The JWT `jku` header (and `iss` claim) come from an unverified, attacker-supplied token.
// Fetching a JWK set from that location is SSRF and lets the attacker supply the
// verification key (CWE-345).
@RestController
public class JkuEndpoint {

  private static final URL TRUSTED_JWKS = trusted();

  private static URL trusted() {
    try {
      return new URL("https://issuer.example.com/.well-known/jwks.json");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  // BAD: `jku` header passed to JwkProviderBuilder(URL).
  @PostMapping("/jku/builder")
  public Object builder(@RequestParam("token") String token) throws Exception { // $ Source
    DecodedJWT decoded = JWT.decode(token);
    Claim jku = decoded.getHeaderClaim("jku");
    JwkProvider provider = new JwkProviderBuilder(new URL(jku.asString())).build(); // $ Alert
    return provider.get(decoded.getKeyId());
  }

  // BAD: `jku` header passed to UrlJwkProvider(URL).
  @PostMapping("/jku/url-provider")
  public Object urlProvider(@RequestParam("token") String token) throws Exception { // $ Source
    DecodedJWT decoded = JWT.decode(token);
    URL jku = new URL(decoded.getHeaderClaim("jku").asString());
    return new UrlJwkProvider(jku).get(decoded.getKeyId()); // $ Alert
  }

  // BAD: unverified `iss` claim used as the JWKS domain.
  @PostMapping("/jku/issuer")
  public Object issuer(@RequestParam("token") String token) throws Exception { // $ Source
    DecodedJWT decoded = JWT.decode(token);
    return new JwkProviderBuilder(decoded.getIssuer()).build().get(decoded.getKeyId()); // $ Alert
  }

  // GOOD: JWKS location is fixed; only the key id comes from the token.
  @PostMapping("/jku/fixed")
  public Object fixed(@RequestParam("token") String token) throws Exception {
    DecodedJWT decoded = JWT.decode(token);
    return new JwkProviderBuilder(TRUSTED_JWKS).build().get(decoded.getKeyId());
  }

  // GOOD: `jku` must equal the trusted location. Stock `java/ssrf` has no equality-guard
  // barrier, so this is a known false positive of the stock query.
  @PostMapping("/jku/allowlisted")
  public Object allowlisted(@RequestParam("token") String token) throws Exception { // $ SPURIOUS: Source
    DecodedJWT decoded = JWT.decode(token);
    String jku = decoded.getHeaderClaim("jku").asString();
    if (!TRUSTED_JWKS.toString().equals(jku)) {
      throw new SecurityException("untrusted jku");
    }
    return new UrlJwkProvider(new URL(jku)).get(decoded.getKeyId()); // $ SPURIOUS: Alert
  }
}
