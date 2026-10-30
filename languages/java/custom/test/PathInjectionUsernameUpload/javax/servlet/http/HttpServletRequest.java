package javax.servlet.http;

import javax.servlet.ServletRequest;

public interface HttpServletRequest extends ServletRequest {
    Part getPart(String name);
}
