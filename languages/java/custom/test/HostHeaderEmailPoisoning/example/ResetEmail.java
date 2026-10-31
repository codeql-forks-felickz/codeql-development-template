package example;

class ResetEmail {
  static ResetEmailBuilder builder() {
    return new ResetEmailBuilder();
  }
}

class ResetEmailBuilder {
  ResetEmailBuilder contents(String contents) {
    return this;
  }

  ResetEmail build() {
    return new ResetEmail();
  }
}
