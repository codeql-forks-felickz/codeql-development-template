package org.example.jsp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashMe {
  public static String hashMe(String str) {
    StringBuffer sb = null;
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(str.getBytes());
      byte[] byteData = md.digest();
      sb = new StringBuffer();
      for (int i = 0; i < byteData.length; i++) {
        sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
      }
    } catch (NoSuchAlgorithmException e) {
    }
    return sb.toString();
  }
}
