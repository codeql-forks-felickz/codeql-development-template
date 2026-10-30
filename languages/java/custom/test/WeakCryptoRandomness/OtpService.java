import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class OtpService {

  static class OtpEntity {
    private String otpHash;

    public void setOtpHash(String otpHash) {
      this.otpHash = otpHash;
    }
  }

  static void sendEmail(String to, String subject, String body) {}

  static void store(String email, String code) {}

  // BAD: 4-digit OTP generated with an unseeded java.util.Random (reported pattern).
  public void requestOtpLevel1(String email) {
    Random random = new Random();
    String otp = String.format("%04d", random.nextInt(10000)); // $ Alert
    store(email, otp);
  }

  // BAD: OTP generated with a time-seeded java.util.Random.
  public void requestOtpLevel2(String email) {
    Random seededRandom = new Random(System.currentTimeMillis());
    String otp = String.format("%06d", seededRandom.nextInt(1000000)); // $ Alert
    sendEmail(email, "Your OTP", "Your OTP is: " + otp);
  }

  // BAD: OTP passed directly to an OTP setter.
  public void requestOtpSetter(OtpEntity entity) {
    entity.setOtpHash(String.valueOf(new Random().nextInt(1000000))); // $ Alert
  }

  // BAD: method that generates an OTP returns a weak random value.
  public String generateOtp() {
    return Integer.toString(ThreadLocalRandom.current().nextInt(100000, 1000000)); // $ Alert
  }

  // BAD: verification code generated with Math.random().
  public void sendVerificationCode(String email) {
    int verificationCode = (int) (Math.random() * 1000000); // $ Alert
    store(email, String.valueOf(verificationCode));
  }

  // BAD: password-reset token generated with java.util.Random.
  public String createResetToken() {
    String resetToken = Long.toHexString(new Random().nextLong()); // $ Alert
    return resetToken;
  }

  // GOOD: OTP generated with SecureRandom.
  public void requestOtpSecure(String email) {
    SecureRandom random = new SecureRandom();
    String otp = String.format("%06d", random.nextInt(1000000));
    store(email, otp);
  }

  // GOOD: java.util.Random used for a non-security value.
  public void retryWithJitter() throws InterruptedException {
    Random random = new Random();
    long backoffDelay = random.nextInt(500);
    Thread.sleep(backoffDelay);
  }

  // GOOD: names that merely contain the letters "otp" are not OTPs.
  public int footprint() {
    int footprintSize = new Random().nextInt(10);
    return footprintSize;
  }

  // GOOD (for this query): already reported by the standard java/insecure-randomness query.
  public void createOtpPassword(String email) {
    String otpPassword = Integer.toString(new Random().nextInt());
    store(email, otpPassword);
  }
}
