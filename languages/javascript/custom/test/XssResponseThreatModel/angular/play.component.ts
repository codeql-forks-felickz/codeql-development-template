import { Component, Injectable } from '@angular/core'
import { HttpClient } from '@angular/common/http'

@Injectable({ providedIn: 'root' })
export class LiveService {
  constructor (private http: HttpClient) {}

  getMessages (id: string) {
    return this.http.get('/lives/' + id + '/messages') // $ Source[js/xss]
  }
}

// Constructor-injected HttpClient is already recognized by the stock library.
@Component({ selector: 'app-play', template: '<div id="messages"></div>' })
export class PlayComponent {
  constructor (private liveService: LiveService) {}

  getMessages (id: string) {
    this.liveService.getMessages(id).subscribe((response) => {
      (response as any[]).forEach((message) => {
        const name = document.createElement('b')
        name.innerHTML = message.user.username // $ Alert[js/xss]
        const content = document.createElement('p')
        content.innerHTML = message.content // $ Alert[js/xss]
        const safe = document.createElement('p')
        safe.textContent = message.content
      })
    })
  }
}
