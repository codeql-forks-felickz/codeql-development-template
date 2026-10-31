package com.example.xxe;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimpleXXE {
  private final CommentsCache comments = new CommentsCache();

  @PostMapping(path = "/xxe/simple")
  @ResponseBody
  public String createNewComment(@RequestBody String commentStr) throws Exception { // $ Source
    return comments.parseXml(commentStr, false).toString();
  }

  @PostMapping(path = "/xxe/simple-safe")
  @ResponseBody
  public String createNewCommentSafe(@RequestBody String commentStr) throws Exception {
    return comments.parseXmlHardened(commentStr).toString();
  }
}
