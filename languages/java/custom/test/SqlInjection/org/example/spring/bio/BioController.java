package org.example.spring.bio;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Profile bio endpoints: the bio text reaches the database layer inside a model object, and the
// user id is converted to an int before it reaches the database layer.
@RestController
public class BioController {
  final DatabaseManager databaseManager;

  public BioController(DatabaseManager databaseManager) {
    this.databaseManager = databaseManager;
  }

  @PostMapping("/user/{id}/bio")
  public void postBio(
      @PathVariable("id") String userId,
      @RequestParam String bioText, // $ Source
      @RequestParam(required = false, defaultValue = "false") boolean enableMarkdown) {
    Bio bio = new Bio(Integer.parseInt(userId), bioText);
    boolean success;
    if (databaseManager.getBio(Integer.parseInt(userId)) != null) {
      success = databaseManager.updateBio(bio);
    } else {
      success = databaseManager.insertBio(bio);
    }
  }

  @GetMapping("/user/{id}/bio")
  public Bio getBio(@PathVariable("id") String userId) {
    return databaseManager.getBio(Integer.parseInt(userId));
  }
}
