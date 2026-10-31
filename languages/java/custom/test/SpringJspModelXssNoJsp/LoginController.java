import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

// No JSP view resolver is configured in this project (for example, views are
// rendered by an auto-escaping template engine), so model attributes are not
// reported.
@Controller
public class LoginController {
  @GetMapping("/login")
  public String showLogin(@RequestParam("username") String username, Model model) {
    model.addAttribute("username", username);
    return "login";
  }
}
