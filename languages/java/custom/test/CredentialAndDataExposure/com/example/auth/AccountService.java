package com.example.auth;

import javax.crypto.spec.PBEKeySpec;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

public class AccountService {
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  public UserAccount createPlain(String username, String rawPassword) { // $ Source
    UserAccount account = new UserAccount();
    account.setUsername(username);
    // BAD: the JPA entity persists the password in cleartext.
    account.setPassword(rawPassword); // $ Alert
    return account;
  }

  public UserAccount createHashed(String username, String rawPassword) {
    UserAccount account = new UserAccount();
    account.setUsername(username);
    // GOOD: only the bcrypt hash is persisted.
    account.setPassword(encoder.encode(rawPassword));
    return account;
  }

  public void createHashedThroughHelper(UserAccount account, String rawPassword) {
    // GOOD: the helper receives only the bcrypt hash.
    persistHashedPassword(account, encoder.encode(rawPassword));
  }

  public void createMixedThroughHelper(UserAccount account) {
    String password = System.console().readLine();
    // BAD: this caller passes an unprotected password to the helper.
    persistPassword(account, password); // $ Source
    // GOOD: this caller passes only the bcrypt hash to the same helper.
    persistPassword(account, encoder.encode(password));
  }

  public void createPlainThroughHelper(UserAccount account) {
    String password = System.console().readLine();
    persistPlainPassword(account, password);
  }

  public UserAccount createDecrypted(String password) { // $ Source
    UserAccount account = new UserAccount();
    account.setPassword(decryptPassword(password)); // $ Alert
    return account;
  }

  public UserAccount createWithNoOpEncoder(String password) { // $ Source
    UserAccount account = new UserAccount();
    NoOpPasswordEncoder noOpEncoder =
        (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    account.setPassword(noOpEncoder.encode(password)); // $ Alert
    return account;
  }

  public HashedUserAccount createHashedBySetter(String rawPassword) {
    HashedUserAccount account = new HashedUserAccount();
    account.setPassword(rawPassword);
    return account;
  }

  public PBEKeySpec deriveWeakKey(String password) { // $ Source
    return new PBEKeySpec(password.toCharArray(), new byte[16], 1, 128); // $ Alert
  }

  public PBEKeySpec deriveStrongKey(String password) {
    return new PBEKeySpec(password.toCharArray(), new byte[16], 600000, 128);
  }

  public boolean verifyWithWeakBcrypt(String password, String hash) { // $ Source
    BCryptPasswordEncoder weakEncoder = new BCryptPasswordEncoder(4);
    return weakEncoder.matches(password, hash); // $ Alert
  }

  public boolean verifyWithStrongBcrypt(String password, String hash) {
    BCryptPasswordEncoder strongEncoder = new BCryptPasswordEncoder(10);
    return strongEncoder.matches(password, hash);
  }

  private String decryptPassword(String password) {
    return password;
  }

  private void persistPassword(UserAccount account, String password) {
    account.setPassword(password); // $ Alert
  }

  private void persistPlainPassword(UserAccount account, String password) { // $ Source
    account.setPassword(password); // $ Alert
  }

  private void persistHashedPassword(UserAccount account, String password) {
    account.setPassword(password);
  }
}
