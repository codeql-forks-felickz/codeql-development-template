package com.example.auth;

import javax.persistence.Entity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Entity
public class HashedUserAccount {
  private String password;
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

  public void setPassword(String password) {
    this.password = encoder.encode(password);
  }
}
