import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;

@Controller
public class LoginController {

  // Reduced from the linked finding: the `username` query parameter is copied
  // into the model and rendered by login.jsp without contextual encoding.
  @RequestMapping(value = "/login", method = RequestMethod.GET)
  public String showLogin(
      @RequestParam(value = "target", required = false) String target, // $ Source
      @RequestParam(value = "username", required = false) String username, // $ Source
      Model model) {
    if (username == null) {
      username = "";
    }
    if (target == null) {
      target = "";
    }
    model.addAttribute("username", username); // $ Alert
    model.addAttribute("target", target); // $ Alert
    return "login";
  }

  @GetMapping("/profile")
  public String showProfile(@RequestParam("name") String name, ModelMap model) { // $ Source
    model.addAttribute("name", "Hello " + name); // $ Alert
    return "profile";
  }

  @GetMapping("/search")
  public ModelAndView search(@RequestParam("q") String q) { // $ Source
    ModelAndView mav = new ModelAndView("search");
    mav.addObject("query", q); // $ Alert
    return mav;
  }

  @GetMapping("/item")
  public ModelAndView item(@RequestParam("id") String id) { // $ Source
    return new ModelAndView("item", "id", id); // $ Alert
  }

  // Safe: value is HTML-escaped before it reaches the model.
  @GetMapping("/login-safe")
  public String showLoginSafe(@RequestParam("username") String username, Model model) {
    model.addAttribute("username", HtmlUtils.htmlEscape(username));
    return "login";
  }

  // Safe: numeric values cannot carry markup.
  @GetMapping("/page")
  public String page(@RequestParam("page") int page, Model model) {
    model.addAttribute("page", page);
    return "list";
  }

  // Safe: constant, not user controlled.
  @GetMapping("/about")
  public String about(Model model) {
    model.addAttribute("title", "About us");
    return "about";
  }

  // Not a model attribute: covered (or excluded) by the standard java/xss query.
  @GetMapping("/echo")
  @ResponseBody
  public ResponseEntity<Banner> echo(@RequestParam("banner") String banner) {
    return ResponseEntity.ok(new Banner(banner));
  }

  static class Banner {
    String content;

    Banner(String content) {
      this.content = content;
    }
  }
}
