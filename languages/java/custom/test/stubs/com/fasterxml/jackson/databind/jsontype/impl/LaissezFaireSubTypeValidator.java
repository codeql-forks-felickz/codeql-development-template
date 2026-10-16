package com.fasterxml.jackson.databind.jsontype.impl;

import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

public final class LaissezFaireSubTypeValidator extends PolymorphicTypeValidator {
  public static final LaissezFaireSubTypeValidator instance = new LaissezFaireSubTypeValidator();
}
