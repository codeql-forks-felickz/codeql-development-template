package utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.CloseableThreadContext;
import org.apache.logging.log4j.ThreadContext;

public class ShepherdLogManager {

  public static void setRequestIp(String theIp, String theForwardedIp, String userName) {
    if (theForwardedIp != null && !theForwardedIp.isEmpty()) {
      ThreadContext.put("RemoteAddress", userName + " at " + theIp + " from " + theForwardedIp); // $ Alert
    } else {
      ThreadContext.put("RemoteAddress", userName + " at " + theIp + " from ?.?.?.?");
    }
  }

  // Mirrors the reported pattern: X-Forwarded-For is passed unvalidated into the MDC.
  public void logRequest(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For"); // $ Source
    setRequestIp(request.getRemoteAddr(), forwarded, "UnknownUser");
  }

  public void otherThreadContextWrites(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For"); // $ Source
    ThreadContext.putIfNull("ip", forwarded); // $ Alert
    ThreadContext.push(forwarded); // $ Alert
    ThreadContext.push("ip={}", forwarded); // $ Alert
    Map<String, String> ctx = new HashMap<>();
    ctx.put("ip", forwarded);
    ThreadContext.putAll(ctx); // $ Alert
    try (CloseableThreadContext.Instance c = CloseableThreadContext.put("ip", forwarded)) { // $ Alert
      c.put("ip2", forwarded); // $ Alert
    }
    List<String> messages = new ArrayList<>();
    messages.add(forwarded);
    CloseableThreadContext.pushAll(messages).close(); // $ Alert
  }

  public void safeThreadContextWrites(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    // Constant value: no taint.
    ThreadContext.put("ip", "unknown");
    // Key is attacker controlled but only values are rendered by %X{key}.
    ThreadContext.put(forwarded, "constant");
    // CR/LF neutralized.
    ThreadContext.put("ip", forwarded.replace("\n", "").replace("\r", ""));
    ThreadContext.put("ip", forwarded.replaceAll("[^a-zA-Z0-9.:, ]", ""));
    // Guarded against line breaks.
    if (!forwarded.contains("\n") && !forwarded.contains("\r")) {
      ThreadContext.put("ip", forwarded);
    }
    // Reading from the context is not a sink.
    ThreadContext.get(forwarded);
  }
}
