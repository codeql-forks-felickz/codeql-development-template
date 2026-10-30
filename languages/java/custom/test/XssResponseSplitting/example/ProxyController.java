package example;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.message.BasicHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProxyController {

  // BAD: request parameter placed verbatim into an outgoing HttpClient 4.x request header.
  @RequestMapping("/proxy")
  public void proxyAddHeader(@RequestParam String url, @RequestParam String header) { // $ Source
    HttpGet httpget = new HttpGet(url);
    httpget.addHeader("Accept-Language", header); // $ Alert
  }

  // BAD: setHeader is equally vulnerable.
  @RequestMapping("/proxy-set")
  public void proxySetHeader(@RequestParam String url, @RequestParam String header) { // $ Source
    HttpGet httpget = new HttpGet(url);
    httpget.setHeader("Accept-Language", header); // $ Alert
  }

  // BAD: user-controlled header name.
  @RequestMapping("/proxy-name")
  public void proxyHeaderName(@RequestParam String url, @RequestParam String name) { // $ Source
    HttpGet httpget = new HttpGet(url);
    httpget.addHeader(name, "value"); // $ Alert
  }

  // BAD: header built via BasicHeader.
  @RequestMapping("/proxy-basic")
  public void proxyBasicHeader(@RequestParam String url, @RequestParam String header) { // $ Source
    HttpGet httpget = new HttpGet(url);
    httpget.addHeader(new BasicHeader("Accept-Language", header)); // $ Alert
  }

  // BAD: header added through RequestBuilder.
  @RequestMapping("/proxy-builder")
  public void proxyBuilder(@RequestParam String url, @RequestParam String header) { // $ Source
    RequestBuilder.get(url).addHeader("Accept-Language", header); // $ Alert
  }

  // BAD: Apache HttpClient 5.x request.
  @RequestMapping("/proxy5")
  public void proxyHttpClient5(@RequestParam String url, @RequestParam String header) { // $ Source
    org.apache.hc.client5.http.classic.methods.HttpGet httpget =
        new org.apache.hc.client5.http.classic.methods.HttpGet(url);
    httpget.addHeader("Accept-Language", header); // $ Alert
  }

  // BAD: Apache HttpClient 5.x request builder.
  @RequestMapping("/proxy5-builder")
  public void proxyHttpClient5Builder(@RequestParam String url, @RequestParam String header) { // $ Source
    org.apache.hc.core5.http.io.support.ClassicRequestBuilder.get(url)
        .addHeader("Accept-Language", header); // $ Alert
  }

  // BAD: inherited setHeader of the generic 5.x AbstractMessageBuilder.
  @RequestMapping("/proxy5-builder-set")
  public void proxyHttpClient5BuilderSet(@RequestParam String url, @RequestParam String header) { // $ Source
    org.apache.hc.core5.http.io.support.ClassicRequestBuilder.get(url)
        .setHeader("Accept-Language", header); // $ Alert
  }

  // GOOD: constant header value.
  @RequestMapping("/proxy-constant")
  public void proxyConstant(@RequestParam String url) {
    HttpGet httpget = new HttpGet(url);
    httpget.addHeader("Accept-Language", "en-US");
  }

  // GOOD: CR and LF characters are removed before use.
  @RequestMapping("/proxy-sanitized")
  public void proxySanitized(@RequestParam String url, @RequestParam String header) {
    HttpGet httpget = new HttpGet(url);
    httpget.addHeader("Accept-Language", header.replaceAll("[\r\n]", ""));
  }

  // GOOD: value converted to a number cannot contain CR or LF.
  @RequestMapping("/proxy-number")
  public void proxyNumber(@RequestParam String url, @RequestParam String count) {
    HttpGet httpget = new HttpGet(url);
    int n = Integer.parseInt(count);
    httpget.addHeader("X-Count", n + "");
  }
}
