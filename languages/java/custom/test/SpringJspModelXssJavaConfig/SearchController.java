import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SearchController {
  @GetMapping("/search")
  public String search(@RequestParam("q") String q, Model model) { // $ Source
    model.addAttribute(q); // $ Alert
    return "search";
  }
}
