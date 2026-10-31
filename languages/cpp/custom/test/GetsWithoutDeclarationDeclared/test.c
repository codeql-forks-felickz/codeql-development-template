/* `gets` is declared, so only the standard `cpp/dangerous-function-overflow` reports it. */
char *gets(char *);
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);

void declared(void) {
  char buf[8];
  gets(buf);
}

void safe(void) {
  char buf[8];
  fgets(buf, sizeof(buf), stdin);
}
