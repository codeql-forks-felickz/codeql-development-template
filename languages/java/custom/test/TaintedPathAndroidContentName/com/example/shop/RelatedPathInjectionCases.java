package com.example.shop;

import java.io.File;
import javax.servlet.http.HttpServletRequest;
import org.apache.taglibs.standard.tag.common.core.ImportSupport;
import org.apache.taglibs.standard.tag.rt.core.ImportTag;

public class RelatedPathInjectionCases {

    private static class SeparateClassRequest {
        private final HttpServletRequest request;

        SeparateClassRequest(HttpServletRequest request) {
            this.request = request;
        }

        String getTheParameter(String name) {
            return request.getParameter(name); // $ Source
        }
    }

    public void probe(HttpServletRequest request) {
        String path = request.getParameter("path"); // $ Source
        if (new File(path).exists()) { // $ Alert
        }
    }

    public void probeWrappedParameter(HttpServletRequest request) {
        String path = new SeparateClassRequest(request).getTheParameter("path");
        if (new File(path).exists()) { // $ Alert
        }
    }

    public void safeProbe(HttpServletRequest request) {
        String path = request.getParameter("path");
        if (path.contains("..") || path.startsWith("/")) {
            return;
        }
        new File(path).exists();
    }

    public void prefixCheckedDelete(HttpServletRequest request) {
        String path = request.getParameter("path"); // $ Source
        if (path.startsWith("/safe_dir/")) {
            new File(path).delete(); // $ Alert
        }
    }

    public void consolePrefixCheckedDelete() {
        String path = System.console().readLine(); // $ Source
        if (path.startsWith("/safe_dir/")) {
            new File(path).delete(); // $ Alert
        }
    }

    public void consoleValidatedDelete() {
        String path = System.console().readLine();
        if (path.contains("..") || path.contains("/") || path.contains("\\")) {
            return;
        }
        new File(path).delete();
    }

    public void validatedDelete(HttpServletRequest request) {
        String path = request.getParameter("path");
        if (path.contains("..") || path.contains("/") || path.contains("\\")) {
            return;
        }
        new File(path).delete();
    }

    public void importTemplate(HttpServletRequest request) {
        String template = request.getParameter("template"); // $ Source
        new ImportSupport().setUrl(template + "_header.html"); // $ Alert
        new ImportTag().setUrl(template + "_footer.html"); // $ Alert
    }

    public void importFixedTemplate() {
        new ImportSupport().setUrl("/dt/basic_header.html");
        new ImportTag().setUrl("/dt/basic_header.html");
    }
}
