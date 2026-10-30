package org.apache.jsp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.PageContext;

// Shape of the servlet that Jasper's jspc generates for a JSP page such as
// `<% if (request.getParameter("err") != null) { out.print(request.getParameter("err")); } %>`.
public final class login_jsp {
  private PageContext pageContext;

  public void _jspService(HttpServletRequest request, HttpServletResponse response)
      throws java.io.IOException {
    JspWriter out = pageContext.getOut();

    out.write("<form>\n<table>\n");
    // `<input value="<%=username%>"/>` compiles to `out.print(username)`.
    String username = request.getParameter("username"); // $ Source
    out.write("<input type=\"text\" name=\"username\" value=\"");
    out.print(username); // $ Alert
    out.write("\"/>\n");

    if (request.getParameter("err") != null) {
      out.print(request.getParameter("err")); // $ Alert
    }
    out.println("<p>" + request.getParameter("msg") + "</p>"); // $ Alert

    // Not reported: numeric value and constant markup.
    out.print(Integer.parseInt(request.getParameter("page")));
    out.print("</table>\n</form>\n");
  }
}
