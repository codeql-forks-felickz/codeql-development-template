package org.springframework.web.bind.annotation;

import java.lang.annotation.*;
import org.springframework.stereotype.Controller;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Controller
public @interface RestController {
  String value() default "";
}
