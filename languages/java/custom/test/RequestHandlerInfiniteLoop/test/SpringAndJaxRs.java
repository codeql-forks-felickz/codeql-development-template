package test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
class SpringInfiniteLoopController {
  @GetMapping("/spin")
  public String spin() {
    while (true) { // $ Alert
      System.out.println("spinning");
    }
  }

  @RequestMapping("/ok")
  public String ok() {
    while (true) {
      if (System.nanoTime() > 0) {
        return "ok";
      }
    }
  }
}

@Path("/jaxrs")
class JaxRsInfiniteLoopResource {
  @GET
  public String spin() {
    while (true) { // $ Alert
      System.out.println("spinning");
    }
  }
}
