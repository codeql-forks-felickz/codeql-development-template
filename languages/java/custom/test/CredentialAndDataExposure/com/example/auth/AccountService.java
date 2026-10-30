package com.example.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

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

  private void persistPassword(UserAccount account, String password) {
    account.setPassword(password); // $ Alert
  }

  private void persistHashedPassword(UserAccount account, String password) {
    account.setPassword(password);
  }
}
