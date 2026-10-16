package javax.servlet.annotation;

public @interface WebServlet {
  String[] urlPatterns() default {};
}
