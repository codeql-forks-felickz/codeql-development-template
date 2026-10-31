import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class LmHash {
    public static byte[] lmDesEncrypt(byte[] key8) throws Exception {
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding"); // $ Alert
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key8, "DES")); // $ Alert
        return des.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
