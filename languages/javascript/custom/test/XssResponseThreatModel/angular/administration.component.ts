import { Component, inject } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { TranslateService } from '@ngx-translate/core'
import { FeedbackService, UserService } from './feedback.service'

@Component({ selector: 'app-administration', template: '<p [innerHTML]="x"></p>' })
export class AdministrationComponent {
  private readonly userService = inject(UserService)
  private readonly feedbackService = inject(FeedbackService)
  private readonly translate = inject(TranslateService)
  private readonly sanitizer = inject(DomSanitizer)
  public userDataSource: any
  public feedbackDataSource: any
  public title: any

  // Not covered: calls on services obtained through `inject(UserService)` are not resolved, so the
  // `HttpClient` response inside `UserService.find` does not reach this callback.
  findAllUsers () {
    this.userService.find().subscribe((users) => {
      this.userDataSource = users
      for (const user of this.userDataSource) {
        user.email = this.sanitizer.bypassSecurityTrustHtml(`<span class="confirmation">${user.email}</span>`) // $ MISSING: Alert[js/xss]
      }
    })
  }

  findAllFeedbacks () {
    this.feedbackService.find().subscribe((feedbacks) => {
      this.feedbackDataSource = feedbacks
      for (const feedback of this.feedbackDataSource) {
        feedback.comment = this.sanitizer.bypassSecurityTrustHtml(feedback.comment) // $ MISSING: Alert[js/xss]
      }
    })
  }

  // Safe: translations are not HTTP response data from the application's API.
  showTitle () {
    this.translate.get('TITLE_ADMINISTRATION').subscribe((title) => {
      this.title = this.sanitizer.bypassSecurityTrustHtml(title)
    })
  }

  // Safe: the response is only used for a count.
  countFeedbacks () {
    this.feedbackService.find().subscribe((feedbacks) => {
      this.title = this.sanitizer.bypassSecurityTrustHtml('<b>' + feedbacks.length + '</b>')
    })
  }
}
