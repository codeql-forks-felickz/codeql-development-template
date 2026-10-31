---
category: newQuery
---

- Added a new query, `rb/cookie-stored-xss`, which finds Rails applications that copy request input into a cookie and later emit that cookie into a page without escaping (for example `cookies[:font] = params[:font]` followed by `<%= raw cookies[:font] %>` in a layout). Such flows are not reported by `rb/reflected-xss` or `rb/stored-xss`, because cookie reads are not considered third-party controllable.
