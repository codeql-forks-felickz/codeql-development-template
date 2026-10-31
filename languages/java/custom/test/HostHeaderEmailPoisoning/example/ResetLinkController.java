package example;

import jakarta.servlet.http.HttpServletRequest;

class ResetLinkController {
  void sendResetLink(HttpServletRequest request) {
    String host = request.getHeader(HttpHeaders.HOST); // $ Source
    ResetEmail.builder()
        .contents(String.format("https://%s/reset/%s", host, "token")) // $ Alert
        .build();
  }

  void useConfiguredHost(HttpServletRequest request) {
    String host = request.getServerName();
    ResetEmail.builder().contents(String.format("https://%s/reset/%s", host, "token")).build();
  }

  void useOtherRequestHeader(HttpServletRequest request) {
    String host = request.getHeader("X-Forwarded-Host");
    ResetEmail.builder().contents(String.format("https://%s/reset/%s", host, "token")).build();
  }
}
