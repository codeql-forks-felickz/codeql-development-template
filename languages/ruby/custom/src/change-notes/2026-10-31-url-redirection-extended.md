---
category: newQuery
---
* Added `rb/url-redirection-extended` (`UrlRedirectExtended/UrlRedirectExtended.ql`), which complements `rb/url-redirection` (CWE-601) and reports only redirects that the shipped query misses:
  * Redirects in non-GET Rails actions (for example a login `create` action) whose target is a conventional redirect-target request parameter such as `params[:url]` or `params[:return_to]`.
  * Redirects to `params.update(...)` / `params.merge!(...)`.
  * `params` passed to `redirect_to` inside standalone top-level methods (controller-action snippets) where no Rails controller class is in the database.
