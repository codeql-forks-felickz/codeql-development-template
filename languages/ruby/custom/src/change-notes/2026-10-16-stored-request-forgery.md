---
category: newQuery
---
* Added a new query, `rb/stored-request-forgery`, to detect server-side request forgery where the request URL comes from a stored ActiveRecord/ORM field (for example `open(user.avatar_url).read`). The standard `rb/request-forgery` query only treats remote HTTP input as a source, so it does not report these second-order flows.
