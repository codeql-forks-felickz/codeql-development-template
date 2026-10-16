package org.springframework.web.servlet;

public class ModelAndView {
  public ModelAndView() {}

  public ModelAndView(String viewName) {}

  public ModelAndView(String viewName, String modelName, Object modelObject) {}

  public ModelAndView addObject(String attributeName, Object attributeValue) {
    return this;
  }

  public ModelAndView addObject(Object attributeValue) {
    return this;
  }

  public void setViewName(String viewName) {}
}
