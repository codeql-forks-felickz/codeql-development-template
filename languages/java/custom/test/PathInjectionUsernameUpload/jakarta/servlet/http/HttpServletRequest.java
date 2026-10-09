package jakarta.servlet.http;

import jakarta.servlet.ServletRequest;

public interface HttpServletRequest extends ServletRequest {
    Part getPart(String name);
}
