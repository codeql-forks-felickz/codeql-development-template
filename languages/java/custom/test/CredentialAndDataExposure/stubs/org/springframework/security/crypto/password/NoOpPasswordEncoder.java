package org.springframework.security.crypto.password;

public final class NoOpPasswordEncoder implements PasswordEncoder {
  public static PasswordEncoder getInstance() {
    return null;
  }

  @Override
  public String encode(CharSequence rawPassword) {
    return rawPassword.toString();
  }
}
