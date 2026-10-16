package org.springframework.security.crypto.bcrypt;

public class BCryptPasswordEncoder {
    public BCryptPasswordEncoder() {}

    public BCryptPasswordEncoder(int strength) {}

    public String encode(CharSequence rawPassword) { return null; }

    public boolean matches(CharSequence rawPassword, String encodedPassword) { return false; }
}
