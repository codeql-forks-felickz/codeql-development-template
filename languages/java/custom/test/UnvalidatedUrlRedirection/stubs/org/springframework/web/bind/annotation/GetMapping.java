package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping
public @interface GetMapping {
  String[] value() default {};
}
