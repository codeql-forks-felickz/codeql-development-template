package org.example;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtils {

    private static final byte[] salt = new byte[16];
    private static final int LOW_ITERATIONS = 10;
    private static final int SAFE_ITERATIONS = 600_000;

    static {
        new SecureRandom().nextBytes(salt);
    }

    // Reduced from the linked finding: PBKDF2 with a single iteration.
    public static SecretKey getKeyFromPassword(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1, 128); // $ Alert
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    // ECB is already reported by the stock java/weak-cryptographic-algorithm query.
    public static byte[] encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    public static KeySpec lowIterationsViaConstant(char[] password) {
        return new PBEKeySpec(password, salt, LOW_ITERATIONS, 256); // $ Alert
    }

    public static KeySpec lowIterationsViaLocal(char[] password) {
        int iterations = 999;
        return new PBEKeySpec(password, salt, iterations); // $ Alert
    }

    public static KeySpec lowIterationsViaHelper(char[] password) {
        return buildSpec(password, 100);
    }

    private static KeySpec buildSpec(char[] password, int iterations) {
        return new PBEKeySpec(password, salt, iterations, 256); // $ Alert
    }

    public static PBEParameterSpec lowIterationsParameterSpec() {
        return new PBEParameterSpec(salt, 5); // $ Alert
    }

    // Safe: iteration counts at or above the threshold.
    public static KeySpec safeIterations(char[] password) {
        return new PBEKeySpec(password, salt, 310000, 256);
    }

    public static KeySpec safeIterationsViaConstant(char[] password) {
        return new PBEKeySpec(password, salt, SAFE_ITERATIONS, 256);
    }

    public static KeySpec thresholdIterations(char[] password) {
        return new PBEKeySpec(password, salt, 1000, 256);
    }

    public static PBEParameterSpec safeParameterSpec() {
        return new PBEParameterSpec(salt, 210000);
    }

    // Safe: password-only spec (no iteration count) and runtime-configured count.
    public static KeySpec passwordOnly(char[] password) {
        return new PBEKeySpec(password);
    }

    public static KeySpec configuredIterations(char[] password, int iterations) {
        return new PBEKeySpec(password, salt, iterations, 256);
    }
}
