package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(method = RequestMethod.POST)
public @interface PostMapping {
  String[] value() default {};
}
