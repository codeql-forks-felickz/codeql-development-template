import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SpringRedirectView {
  private static final List<String> ALLOWED = Arrays.asList("/home", "/feed");

  // vuln-spring: request parameter concatenated into a "redirect:" view name.
  @GetMapping("/support")
  public String support(@RequestParam(required = false) String desk) { // $ Source
    String helpDeskLocation = desk;
    if (helpDeskLocation != null) {
      return "redirect:" + helpDeskLocation; // $ Alert
    }
    return "support";
  }

  // verademo: redirect view name assigned to a local and returned later.
  @GetMapping("/login")
  public String login(@RequestParam(value = "target", required = false) String target) { // $ Source
    String nextView;
    if (target != null && !target.isEmpty() && !target.equals("null")) {
      nextView = "redirect:" + target; // $ Alert
    } else {
      nextView = "redirect:feed";
    }
    return nextView;
  }

  // WebGoat: redirect view name passed to a ModelAndView.
  @GetMapping("/realRedirect")
  public ModelAndView real(@RequestParam("url") String url) { // $ Source
    return new ModelAndView("redirect:" + url); // $ Alert
  }

  @GetMapping("/setViewName")
  public ModelAndView setViewName(@RequestParam("url") String url) { // $ Source
    ModelAndView mav = new ModelAndView();
    mav.setViewName("redirect:" + url); // $ Alert
    return mav;
  }

  // "redirect:/" followed by "/evil.example" yields a scheme-relative URL.
  @GetMapping("/slash")
  public String slash(@RequestParam("next") String next) { // $ Source
    return "redirect:/" + next; // $ Alert
  }

  // Redirect built by a helper called from the controller.
  @GetMapping("/helper")
  public String helper(@RequestParam("next") String next) { // $ Source
    return buildRedirect(next);
  }

  private String buildRedirect(String location) {
    return "redirect:" + location; // $ Alert
  }

  // GOOD: the host and path are fixed, the parameter only selects a sub-path.
  @GetMapping("/fixedPath")
  public String fixedPath(@RequestParam("page") String page) {
    return "redirect:/app/" + page;
  }

  // GOOD: the parameter is only used in the query string.
  @GetMapping("/queryOnly")
  public String queryOnly(@RequestParam("user") String user) {
    return "redirect:login?username=" + user;
  }

  // GOOD: the destination is checked against an allowlist.
  @GetMapping("/allowlisted")
  public String allowlisted(@RequestParam("target") String target) {
    if (ALLOWED.contains(target)) {
      return "redirect:" + target;
    }
    return "redirect:/home";
  }

  // GOOD: "forward:" is a server-side dispatch, not a client redirect.
  @GetMapping("/forward")
  public String forward(@RequestParam("page") String page) {
    return "forward:" + page;
  }

  // GOOD: "redirect:" text that is not used as a view name.
  @GetMapping("/notAView")
  public String notAView(@RequestParam("url") String url) {
    System.out.println("redirect:" + url);
    return "home";
  }
}
