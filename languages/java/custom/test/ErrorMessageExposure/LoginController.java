package app;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.SQLException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {

  private static void query(String user) throws SQLException {
    throw new SQLException("Table 'users' doesn't exist");
  }

  public String displayErrorForWeb(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    String stackTrace = sw.toString();
    pw.flush();
    return stackTrace.replace(System.getProperty("line.separator"), "<br/>\n");
  }

  @RequestMapping("/login")
  public String login(String user, Model model) {
    try {
      query(user);
    } catch (SQLException e) {
      model.addAttribute("error", e.getMessage() + "<br/>" + displayErrorForWeb(e)); // $ Alert
    }
    return "login";
  }

  @RequestMapping("/register")
  public String register(String user, ModelMap model) {
    try {
      query(user);
    } catch (SQLException e) {
      model.addAttribute("error", e.getMessage()); // $ Alert
    }
    return "register";
  }

  @RequestMapping("/profile")
  public ModelAndView profile(String user) {
    ModelAndView mav = new ModelAndView("profile");
    try {
      query(user);
    } catch (SQLException e) {
      mav.addObject("error", displayErrorForWeb(e)); // $ Alert
    }
    return mav;
  }

  @RequestMapping("/safe")
  public String safe(String user, Model model) {
    try {
      query(user);
    } catch (SQLException e) {
      System.err.println(displayErrorForWeb(e));
      model.addAttribute("error", "Login failed. Please try again.");
    }
    return "login";
  }
}
