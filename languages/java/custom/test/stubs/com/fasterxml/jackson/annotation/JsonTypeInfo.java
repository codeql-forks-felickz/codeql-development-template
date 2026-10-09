package com.fasterxml.jackson.annotation;

public @interface JsonTypeInfo {
  public enum As {
    PROPERTY,
    WRAPPER_OBJECT,
    WRAPPER_ARRAY,
    EXTERNAL_PROPERTY,
    EXISTING_PROPERTY
  }
}
