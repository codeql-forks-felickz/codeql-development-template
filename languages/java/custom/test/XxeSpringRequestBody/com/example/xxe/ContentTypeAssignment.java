package com.example.xxe;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContentTypeAssignment {
  private final CommentsCache comments = new CommentsCache();

  @PostMapping(path = "/xxe/content-type")
  @ResponseBody
  public String createNewUser(
      @RequestBody String commentStr, // $ Source
      @RequestHeader("Content-Type") String contentType)
      throws Exception {
    if (null != contentType && contentType.contains("application/xml")) {
      return comments.parseXml(commentStr, false).toString();
    }
    return "";
  }

  @PostMapping(path = "/xxe/content-type-safe")
  @ResponseBody
  public String createNewUserSafe(
      @RequestBody String commentStr, @RequestHeader("Content-Type") String contentType)
      throws Exception {
    if (null != contentType && contentType.contains("application/xml")) {
      return comments.parseXmlHardened(commentStr).toString();
    }
    return "";
  }
}
