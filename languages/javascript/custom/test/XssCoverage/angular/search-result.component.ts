import { ActivatedRoute } from '@angular/router'
import { Component, inject } from '@angular/core'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'

// Angular 14+ `inject()`-based DI: the injected services have no type annotation.
@Component({ selector: 'app-search-result', template: '<span [innerHTML]="searchValue"></span>' })
export class SearchResultComponent {
  private readonly route = inject(ActivatedRoute)
  private readonly sanitizer = inject(DomSanitizer)
  public searchValue?: SafeHtml

  filterTable () {
    let queryParam: string = this.route.snapshot.queryParams.q // $ Source[js/xss]
    if (queryParam) {
      queryParam = queryParam.trim()
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam) // $ Alert[js/xss]
    }
  }

  fromParamMap () {
    const name = this.route.snapshot.queryParamMap.get('name') // $ Source[js/xss]
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(name) // $ Alert[js/xss]
  }

  fromSubscribe () {
    this.route.queryParams.subscribe((params) => { // $ Source[js/xss]
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(params.q) // $ Alert[js/xss]
    })
  }

  fromFragment () {
    const frag = this.route.snapshot.fragment // $ Source[js/xss]
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(frag) // $ Alert[js/xss]
  }

  fromParamsToScript () {
    const code = this.route.snapshot.params.code // $ Source[js/code-injection]
    return this.sanitizer.bypassSecurityTrustScript(code) // $ Alert[js/code-injection]
  }

  safeConstant () {
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')
  }

  safeSanitizerNotBypassed () {
    const q = this.route.snapshot.queryParams.q
    this.searchValue = q.length
  }
}
