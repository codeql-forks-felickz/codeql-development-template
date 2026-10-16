import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AuthLoginService {

    public boolean login(String password, String storedHash, String salt, String algorithm) {
        switch (algorithm) {
            case "MD5":
                return matchesHash(password, storedHash, "MD5"); // $ Source
            case "SHA1":
                return matchesHash(password, storedHash, "SHA-1"); // $ Source
            default:
                return matchesHash(salt + password, storedHash, "SHA-256"); // $ Source
        }
    }

    private boolean matchesHash(String input, String storedHash, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8)); // $ Alert
            return PasswordHashingUtils.toHex(hash).equalsIgnoreCase(storedHash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] updateDigest(MessageDigest md, char[] passphrase) {
        md.update(new String(passphrase).getBytes()); // $ Alert
        return md.digest();
    }
}
