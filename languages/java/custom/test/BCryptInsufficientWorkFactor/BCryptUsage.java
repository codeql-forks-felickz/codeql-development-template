import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptUsage {
    private static final int WEAK_ROUNDS = 4;
    private static final int bcryptWorkFactor = 12;

    public boolean weakMatch(String password, String hash) {
        BCryptPasswordEncoder weakEncoder = new BCryptPasswordEncoder(4);
        return weakEncoder.matches(password, hash);
    }

    public boolean weakUpgradeEncoding(String hash) {
        BCryptPasswordEncoder weakEncoder = new BCryptPasswordEncoder(4);
        return weakEncoder.upgradeEncoding(hash);
    }

    public String weakConstant(String password) {
        return new BCryptPasswordEncoder(WEAK_ROUNDS).encode(password); // $ Alert
    }

    public BCryptPasswordEncoder weakBeanEncoder() {
        return new BCryptPasswordEncoder(4); // $ Alert
    }

    public void weakEncoderEscapes(BCryptPasswordEncoderConsumer consumer) {
        BCryptPasswordEncoder weakEncoder = new BCryptPasswordEncoder(4); // $ Alert
        weakEncoder.matches("password", "hash");
        consumer.accept(weakEncoder);
    }

    public void weakInvalidStrength() {
        new BCryptPasswordEncoder(-1);
        new BCryptPasswordEncoder(3);
    }

    public String weakJbcrypt(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(6)); // $ Alert
    }

    public String strong(String password) {
        return new BCryptPasswordEncoder(bcryptWorkFactor).encode(password);
    }

    public String defaults(String password) {
        return new BCryptPasswordEncoder().encode(password) + BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public String strongJbcrypt(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(10));
    }

    interface BCryptPasswordEncoderConsumer {
        void accept(BCryptPasswordEncoder encoder);
    }
}
