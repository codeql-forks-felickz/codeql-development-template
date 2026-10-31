package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// CWE-256 / CWE-916: plaintext comparison and fast hashes used for stored passwords.
public class AuthLoginService {
  private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  public AuthUser findUser(String username) {
    return new AuthUser();
  }

  public boolean authenticatePlain(String username, String password) { // $ Source
    AuthUser user = findUser(username);
    // BAD: the submitted password is compared to a cleartext stored password.
    return password != null && password.equals(user.getPassword()); // $ Alert
  }

  public boolean authenticateMd5(String username, String password) { // $ Source
    AuthUser user = findUser(username);
    return matchesHash(password, user.getPassword(), "MD5");
  }

  public boolean authenticateSaltedSha256(String username, String password, String salt) { // $ Source
    AuthUser user = findUser(username);
    return matchesHash(salt + password, user.getPassword(), "SHA-256");
  }

  public boolean authenticateBcrypt(String username, String password) {
    AuthUser user = findUser(username);
    // GOOD: a password hashing function is used.
    return password != null && passwordEncoder.matches(password, user.getPassword());
  }

  public String echoChallengePassword(String password) { // $ Source
    String challengePassword = findPasswordByLevelName("level-1");
    if (password.equals(challengePassword)) { // $ Alert
      return "Correct! " + challengePassword;
    }
    return "Incorrect";
  }

  private String findPasswordByLevelName(String level) {
    return null;
  }

  public boolean confirmMatches(String password, String confirmPassword) {
    // GOOD: two user-supplied values are compared, nothing is read from storage.
    return password.equals(confirmPassword);
  }

  private boolean matchesHash(String input, String storedHash, String algorithm) {
    if (input == null || storedHash == null) return false;
    try {
      MessageDigest digest = MessageDigest.getInstance(algorithm);
      // BAD: a fast message digest is not suitable for password storage.
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8)); // $ Alert
      return bytesToHex(hash).equalsIgnoreCase(storedHash);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String bytesToHex(byte[] data) {
    StringBuilder builder = new StringBuilder();
    for (byte value : data) {
      builder.append(String.format("%02x", value));
    }
    return builder.toString();
  }
}
