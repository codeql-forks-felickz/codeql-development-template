package org.springframework.ui;

import java.util.Map;

public interface Model {
  Model addAttribute(String attributeName, Object attributeValue);

  Model addAttribute(Object attributeValue);

  Model addAllAttributes(Map<String, ?> attributes);

  Map<String, Object> asMap();
}
