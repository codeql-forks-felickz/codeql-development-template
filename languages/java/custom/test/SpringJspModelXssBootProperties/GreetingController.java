import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

// JSP views are configured through Spring Boot's `spring.mvc.view.suffix` property.
@Controller
public class GreetingController {
  @GetMapping("/greeting")
  public String greeting(@RequestParam("name") String name, ModelMap model) { // $ Source
    model.put("name", name); // $ Alert
    return "greeting";
  }

  // Safe: redirect attributes are appended to the redirect URL, not rendered by a view.
  @GetMapping("/greeting-redirect")
  public String greetingRedirect(@RequestParam("name") String name, RedirectAttributes attrs) {
    attrs.addAttribute("name", name);
    return "redirect:/greeting";
  }
}
