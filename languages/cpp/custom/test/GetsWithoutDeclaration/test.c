/* `gets` is not declared, as with glibc headers in C11 and later modes. */
int grantAccess(const char *);
void privilegedAction(void);
int puts(const char *);

/* Broken-Vulnerable-Code-Snippets Buffer Overflow/gets.c */
int login(void) {
  char username[8];
  int allow = 0;
  puts("Enter your username, please: ");
  gets(username); // $ Alert
  if (grantAccess(username)) {
    allow = 1;
  }
  if (allow != 0) {
    privilegedAction();
  }
  return 0;
}
