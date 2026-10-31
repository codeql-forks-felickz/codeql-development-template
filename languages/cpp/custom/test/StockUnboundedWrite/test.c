/* Regression tests showing that stock queries report the Broken-Vulnerable-Code-Snippets
   findings once each snippet is compiled on its own. */
typedef unsigned long size_t;
int sprintf(char *, const char *, ...);
int printf(const char *, ...);
int scanf(const char *, ...);
char *strcpy(char *, const char *);
char *strcat(char *, const char *);
char *getenv(const char *);

/* bof1.c */
void bof1(char **argv) {
  char buf[100];
  sprintf(buf, "%s", argv[1]);
}

/* example1.c */
void scan_string(void) {
  char name[16];
  scanf("%s", name);
}

/* netkit-telnet, after fixing its syntax errors */
void telnet_term(void) {
  char hbuf[256];
  strcpy(hbuf, "TERM=");
  strcat(hbuf, getenv("TERM"));
}

/* strcpy.c, after moving its statements into a function */
void copy_literal(void) {
  char dest[10];
  strcpy(dest, "0123456789abcde");
}

/* FormatString.c, after fixing its syntax errors */
void format_string(char **argv) {
  printf(argv[1]);
}

int main(int argc, char **argv) {
  bof1(argv);
  scan_string();
  telnet_term();
  copy_literal();
  format_string(argv);
  return 0;
}
