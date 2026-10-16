# Client-side cross-site scripting through ng-bind-html with SCE disabled

AngularJS strict contextual escaping (SCE) is what makes `ng-bind-html` safe: values bound with `ng-bind-html` are passed through `$sanitize` unless they were explicitly trusted. Calling `$sceProvider.enabled(false)` turns this off for the whole application, so every `ng-bind-html` binding inserts its value into the DOM as raw HTML.

`js/angular/disabling-sce` reports the configuration change, and `js/xss` does not model `ng-bind-html` as a sink. This query connects the two: it reports untrusted data that reaches a `$scope` property rendered with `ng-bind-html` in an application that disables SCE. Untrusted data includes the usual client-side remote sources (for example `$location.search()`) and the data of responses to AngularJS `$http` requests, because server responses often contain stored or reflected user input, such as an error message that echoes a search term.

The query currently resolves `ng-bind-html` expressions that are a plain scope property (for example `ng-bind-html="search_response"`), and requires SCE to be disabled somewhere in the analyzed code base.

## Recommendation

Do not disable SCE. If raw HTML must be rendered, sanitize it with `$sanitize` before binding it, or only mark values that are known to be safe as trusted with `$sce.trustAsHtml`.

## Example

The search error response reflects the `query` parameter, and the page binds it with `ng-bind-html` after disabling SCE:

```html
<b ng-bind-html="search_response"></b>
<script>
  angular
    .module('pixi', ['ngSanitize'])
    .config(function ($sceProvider) {
      $sceProvider.enabled(false)
    })
    .controller('pixiController', function ($scope, $http) {
      $scope.search = function (query) {
        $http.get('/search/?query=' + query).then(
          function (response) {
            $scope.pictures = response.data
          },
          function (response) {
            $scope.search_response = response.data
          }
        )
      }
    })
</script>
```

Removing the `$sceProvider.enabled(false)` call restores sanitization of `ng-bind-html`. Alternatively, sanitize the value explicitly with `$scope.search_response = $sanitize(response.data)`, or render it as text with `ng-bind`.

## References

- AngularJS: [Strict Contextual Escaping](https://docs.angularjs.org/api/ng/service/$sce).
- AngularJS: [ngBindHtml](https://docs.angularjs.org/api/ng/directive/ngBindHtml).
- OWASP: [DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
