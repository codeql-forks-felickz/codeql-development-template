package org.springframework.ui;

public interface Model {
  Model addAttribute(String attributeName, Object attributeValue);

  Model addAttribute(Object attributeValue);
}
