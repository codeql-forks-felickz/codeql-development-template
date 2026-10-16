package test.annotations;

import java.lang.annotation.*;
import org.springframework.web.bind.annotation.RequestMapping;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping
public @interface AppRequestMapping {
  String value();
}
