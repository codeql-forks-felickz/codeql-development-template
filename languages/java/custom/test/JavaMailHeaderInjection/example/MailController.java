package example;

import javax.mail.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class MailController {
  void submit(HttpServletRequest request) {
    String subject = request.getParameter("subject"); // $ Source
    sendEmailWithAttachment(subject);
  }

  private void sendEmailWithAttachment(String subject) {
    MimeMessage message = new MimeMessage();
    message.setSubject(subject, "UTF-8"); // $ Alert
  }

  void sanitized(HttpServletRequest request) {
    String subject = request.getParameter("subject").replaceAll("[\r\n]", "");
    MimeMessage message = new MimeMessage();
    message.setSubject(subject);
  }

  void constant() {
    MimeMessage message = new MimeMessage();
    message.setSubject("Password reset");
  }

  void responseHeader(HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("X-Subject", request.getParameter("subject"));
  }
}
