package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequestParam {
  String value() default "";

  boolean required() default true;

  String defaultValue() default "";
}
