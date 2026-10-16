import { ActivatedRoute } from '@angular/router'
import { Component } from '@angular/core'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'

// Constructor-based DI with type annotations is already covered by the stock library.
@Component({ selector: 'app-legacy', template: '<span [innerHTML]="value"></span>' })
export class LegacyComponent {
  public value?: SafeHtml

  constructor (private readonly route: ActivatedRoute, private readonly sanitizer: DomSanitizer) {}

  show () {
    const q = this.route.snapshot.queryParams.q // $ Source[js/xss]
    this.value = this.sanitizer.bypassSecurityTrustHtml(q) // $ Alert[js/xss]
  }
}
