typedef unsigned long size_t;
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
void *malloc(size_t);
void free(void *);
void exit(int);
void printLine(const char *);

/* Juliet CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_01 */
void cwe761_bad() {
  char *data = (char *)malloc(100 * sizeof(char));
  if (data == 0) exit(-1);
  data[0] = '\0';
  fgets(data, 100, stdin);
  for (; *data != '\0'; data++) { // $ Source
    if (*data == 'S') {
      printLine("We have a match!");
      break;
    }
  }
  free(data); // $ Alert
}

void offset_bad() {
  char *p = (char *)malloc(16);
  p += 4; // $ Source
  free(p); // $ Alert
}

/* Safe: the original pointer is freed. */
void cwe761_good() {
  char *data = (char *)malloc(100 * sizeof(char));
  char *cursor;
  if (data == 0) exit(-1);
  fgets(data, 100, stdin);
  for (cursor = data; *cursor != '\0'; cursor++) {
    if (*cursor == 'S')
      break;
  }
  free(data);
}

/* Safe: indexing does not move the pointer. */
void index_good() {
  char *p = (char *)malloc(16);
  p[3] = 'a';
  free(p);
}

/* Safe: the pointer is reassigned to a new allocation before the free. */
void reassigned_good() {
  char *p = (char *)malloc(16);
  p++;
  p = (char *)malloc(16);
  free(p);
}
