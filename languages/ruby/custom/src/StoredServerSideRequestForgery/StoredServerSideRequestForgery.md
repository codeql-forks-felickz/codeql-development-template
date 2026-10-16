# Stored server-side request forgery

Server-side request forgery (SSRF) happens when a server makes a network request to a URL that an attacker controls. The standard `rb/request-forgery` query only looks at URLs that come straight from the current HTTP request. This query looks at *stored* (second-order) values instead: URLs or hosts that are read from a database record (for example an ActiveRecord attribute such as `user.avatar_url`), which an earlier request may have filled in with attacker-supplied data.

## Recommendation

Do not make requests to URLs taken from stored user data without validating them. Check the value against an allow-list of known-good URLs or hosts, or build the URL from a fixed scheme and host and only insert the stored value into the path.

## Example

In this example a user can set their `avatar_url` through a profile update. A later request reads it back and fetches it with `Kernel#open`, so an authenticated attacker can make the server request internal services and read the responses:

```ruby
require 'open-uri'

class UserAvatarsController < ActionController::Base
  def show
    user = User.find(params[:id])
    send_data(open(user.avatar_url).read, disposition: 'inline')
  end
end
```

The fix checks the stored URL against an allow-list before fetching it:

```ruby
class UserAvatarsController < ActionController::Base
  ALLOWED_AVATAR_URLS = ["https://cdn.example.com/default.png"]

  def show
    user = User.find(params[:id])
    url = user.avatar_url
    if ALLOWED_AVATAR_URLS.include?(url)
      send_data(URI.open(url).read, disposition: 'inline')
    end
  end
end
```

## References

- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
