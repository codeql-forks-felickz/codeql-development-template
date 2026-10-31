typedef unsigned long size_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
int printf(const char *, ...);
void *memset(void *, int, size_t);

/* Dereferences `line` whenever it is non-null (Juliet `printLine`). */
void printLine(const char *line) {
  if (line != NULL) {
    printf("%s\n", line);
  }
}

/* Early-return null check, then an unconditional dereference. */
void firstChar(const char *p) {
  if (!p)
    return;
  printf("%c\n", p[0]);
}

/* Dereference also depends on an unrelated flag: not always dereferenced. */
void maybePrint(const char *p, int verbose) {
  if (p != NULL && verbose) {
    printf("%s\n", p);
  }
}

/* Only prints the pointer value: never dereferenced. */
void printAddress(const char *p) {
  if (p != NULL) {
    printf("%p\n", p);
  }
}

/* No null check at all: already reported by cpp/use-after-free. */
void printAlways(const char *p) { printf("%s\n", p); }

void bad_printLine() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  memset(data, 'A', 100 - 1);
  data[100 - 1] = '\0';
  free(data);
  printLine(data); // BAD
}

void bad_firstChar() {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  data[0] = 'a';
  free(data);
  firstChar(data); // BAD
}

void good_resetToNull() {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  data[0] = '\0';
  free(data);
  data = NULL;
  printLine(data); // GOOD: pointer cleared after free
}

void good_useBeforeFree() {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  data[0] = '\0';
  printLine(data); // GOOD: used before free
  free(data);
}

void good_conditionalCallee(int verbose) {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  free(data);
  maybePrint(data, verbose); // GOOD (not reported): callee only dereferences under an extra condition
}

void good_addressOnly() {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  free(data);
  printAddress(data); // GOOD: pointer value only
}

void stock_printAlways() {
  char *data = (char *)malloc(10);
  if (data == NULL) exit(-1);
  free(data);
  printAlways(data); // not reported here: covered by cpp/use-after-free
}
