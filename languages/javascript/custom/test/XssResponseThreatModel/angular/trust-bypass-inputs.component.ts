import { Component, inject } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import jwtDecode from 'jwt-decode'

function encodeForHTML (value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

@Component({ selector: 'app-trust-bypass-inputs', template: '' })
export class TrustBypassInputsComponent {
  private readonly sanitizer = inject(DomSanitizer)
  html: unknown

  async loadAccount () {
    const account = await fetch('/api/account').then((response) => response.json()) // $ Source[js/xss]
    this.html = this.sanitizer.bypassSecurityTrustHtml(account.lastLoginIp) // $ Alert[js/xss]
    this.html = this.sanitizer.bypassSecurityTrustHtml(jwtDecode(account.token).lastLoginIp) // $ Alert[js/xss]

    const unsafeLink = document.createElement('a')
    unsafeLink.setAttribute('href', account.website) // $ Alert[js/xss]
    document.body.appendChild(unsafeLink)

    const encodedLink = document.createElement('a')
    encodedLink.setAttribute('href', encodeForHTML(account.website)) // $ MISSING: Alert[js/xss]
    document.body.appendChild(encodedLink)
    document.createElement('a').href = 'https://example.com/'
  }

  useConstant () {
    this.html = this.sanitizer.bypassSecurityTrustHtml(
      jwtDecode('******')
        .lastLoginIp
    )
  }
}
