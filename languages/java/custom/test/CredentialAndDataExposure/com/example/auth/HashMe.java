package com.example.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashMe {
  public static String hashMe(String str) {
    StringBuffer sb = new StringBuffer();
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(str.getBytes()); // $ Alert
      byte[] byteData = md.digest();
      for (int i = 0; i < byteData.length; i++) {
        sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
      }
    } catch (NoSuchAlgorithmException e) {
    }
    return sb.toString();
  }

  public static String checksum(byte[] fileContents) throws NoSuchAlgorithmException {
    // GOOD: hashing non-credential data with a fast digest is fine.
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(fileContents);
    return new String(md.digest());
  }
}
