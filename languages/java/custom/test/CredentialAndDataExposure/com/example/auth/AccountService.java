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
}
