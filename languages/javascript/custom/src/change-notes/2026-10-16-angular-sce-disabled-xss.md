---
category: newQuery
---

- Added a new query, `js/angular/sce-disabled-xss`, which finds untrusted data (client-side remote sources and AngularJS `$http` response data) rendered with `ng-bind-html` in AngularJS applications that disable strict contextual escaping with `$sceProvider.enabled(false)`. `js/angular/disabling-sce` only reports the configuration change, and `js/xss` does not treat `ng-bind-html` as a sink.
