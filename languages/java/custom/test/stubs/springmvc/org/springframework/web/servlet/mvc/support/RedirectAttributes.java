package org.springframework.web.servlet.mvc.support;

import org.springframework.ui.Model;

public interface RedirectAttributes extends Model {
  RedirectAttributes addAttribute(String attributeName, Object attributeValue);

  RedirectAttributes addFlashAttribute(String attributeName, Object attributeValue);
}
