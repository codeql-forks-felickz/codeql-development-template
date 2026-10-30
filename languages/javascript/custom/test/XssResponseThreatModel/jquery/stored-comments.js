// Stored XSS: comment text returned by the API is substituted into an HTML template and appended.
$(document).ready(function () {
  var html = '<li class="comment"><h4 class="user">USER</h4><p>COMMENT</p></li>';

  function getComments() {
    $("#list").empty();
    $.get("CrossSiteScriptingStored/stored-xss", function (result, status) { // $ Source[js/xss]
      for (var i = 0; i < result.length; i++) {
        var comment = html.replace("USER", result[i].user);
        comment = comment.replace("COMMENT", result[i].text);
        $("#list").append(comment); // $ Alert[js/xss]
        $("#count").text(result[i].text);
      }
    });
  }

  getComments();
});
