package org.springframework.web.servlet;

public class ModelAndView {
  public ModelAndView(String viewName) {}

  public ModelAndView addObject(String attributeName, Object attributeValue) {
    return this;
  }

  public ModelAndView addObject(Object attributeValue) {
    return this;
  }
}
