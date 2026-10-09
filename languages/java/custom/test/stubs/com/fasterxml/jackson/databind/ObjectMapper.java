package com.fasterxml.jackson.databind;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import java.io.IOException;

public class ObjectMapper {
  public enum DefaultTyping {
    JAVA_LANG_OBJECT,
    OBJECT_AND_NON_CONCRETE,
    NON_CONCRETE_AND_ARRAYS,
    NON_FINAL,
    EVERYTHING
  }

  public ObjectMapper() {}

  public ObjectMapper enableDefaultTyping() {
    return this;
  }

  public ObjectMapper enableDefaultTyping(DefaultTyping dti) {
    return this;
  }

  public ObjectMapper activateDefaultTyping(PolymorphicTypeValidator ptv) {
    return this;
  }

  public ObjectMapper activateDefaultTyping(PolymorphicTypeValidator ptv, DefaultTyping applicability) {
    return this;
  }

  public ObjectMapper activateDefaultTyping(
      PolymorphicTypeValidator ptv, DefaultTyping applicability, JsonTypeInfo.As includeAs) {
    return this;
  }

  public ObjectMapper activateDefaultTypingAsProperty(
      PolymorphicTypeValidator ptv, DefaultTyping applicability, String propertyName) {
    return this;
  }

  public <T> T readValue(String content, Class<T> valueType) throws IOException {
    return null;
  }

  public <T> T readValue(byte[] src, Class<T> valueType) throws IOException {
    return null;
  }
}
