import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'

@Injectable({ providedIn: 'root' })
export class FeedbackService {
  private readonly http = inject(HttpClient)
  private readonly host = '/api/Feedbacks'

  find (params?: any) {
    return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }
}

@Injectable({ providedIn: 'root' })
export class UserService {
  private readonly http = inject(HttpClient)

  find () {
    return this.http.get('/rest/user/authentication-details/').pipe(map((response: any) => response.data))
  }
}
