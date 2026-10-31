import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

// Stored XSS: database-sourced content is formatted into an HTML fragment and
// returned as `text/html` from a `@ResponseBody` handler. The stock `java/xss`
// query reports this only when the `database` threat model is enabled (see
// XSS.ext.yml). With the default `remote` threat model there is no source.
@Controller
public class FeedController {
  private static final String TEMPLATE = "<li><p>%s</p><span>by %s</span></li>";

  private ResultSet query() throws SQLException {
    Connection connect = DriverManager.getConnection("jdbc:mysql://localhost/blab");
    PreparedStatement feedSql = connect.prepareStatement("SELECT blab, name FROM blabs");
    return feedSql.executeQuery();
  }

  @RequestMapping(value = "/morefeed", method = RequestMethod.GET, produces = "text/html;charset=UTF-8")
  @ResponseBody
  public String getMoreFeed() throws SQLException {
    ResultSet results = query();
    StringBuilder ret = new StringBuilder();
    while (results.next()) {
      ret.append(String.format(TEMPLATE, results.getString(1), results.getString(2))); // $ Source
    }
    return ret.toString(); // $ Alert
  }

  // Safe: each database value is HTML-escaped before it is formatted.
  @RequestMapping(value = "/morefeed-safe", method = RequestMethod.GET, produces = "text/html;charset=UTF-8")
  @ResponseBody
  public String getMoreFeedSafe() throws SQLException {
    ResultSet results = query();
    StringBuilder ret = new StringBuilder();
    while (results.next()) {
      ret.append(
          String.format(
              TEMPLATE,
              HtmlUtils.htmlEscape(results.getString(1)),
              HtmlUtils.htmlEscape(results.getString(2))));
    }
    return ret.toString();
  }

  // Safe: the response is declared as JSON, which browsers do not render as HTML.
  @RequestMapping(value = "/morefeed-json", method = RequestMethod.GET, produces = "application/json")
  @ResponseBody
  public String getMoreFeedJson() throws SQLException {
    ResultSet results = query();
    StringBuilder ret = new StringBuilder();
    while (results.next()) {
      ret.append(results.getString(1));
    }
    return ret.toString();
  }
}
