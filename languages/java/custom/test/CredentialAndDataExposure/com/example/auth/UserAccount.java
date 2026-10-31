package com.example.auth;

import javax.persistence.Entity;

@Entity
public class UserAccount {
  private String username;
  private String password;

  public void setUsername(String username) {
    this.username = username;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
