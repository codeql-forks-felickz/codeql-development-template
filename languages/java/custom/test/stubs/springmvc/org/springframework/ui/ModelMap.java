package org.springframework.ui;

import java.util.LinkedHashMap;

public class ModelMap extends LinkedHashMap<String, Object> {
  public ModelMap addAttribute(String attributeName, Object attributeValue) {
    return this;
  }

  public ModelMap addAttribute(Object attributeValue) {
    return this;
  }
}
