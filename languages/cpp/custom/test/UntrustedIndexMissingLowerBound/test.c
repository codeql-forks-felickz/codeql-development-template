typedef unsigned long size_t;
typedef long ssize_t;
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
ssize_t recv(int, void *, size_t, int);
int atoi(const char *);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
void printLine(const char *);

int readIndexSocket(int s) {
  char inputBuffer[14];
  int data = -1;
  ssize_t r = recv(s, inputBuffer, 13, 0); // $ Source
  if (r > 0) {
    inputBuffer[r] = '\0';
    data = atoi(inputBuffer);
  }
  return data;
}

/* Juliet CWE124_Buffer_Underwrite__CWE839_fgets_01 */
void cwe124_fgets_bad() {
  int data = -1;
  char inputBuffer[14] = "";
  if (fgets(inputBuffer, 14, stdin) != 0) // $ Source
    data = atoi(inputBuffer);
  {
    int buffer[10] = {0};
    if (data < 10) {
      buffer[data] = 1; // $ Alert
    }
  }
}

/* Juliet CWE124_Buffer_Underwrite__CWE839_listen_socket_01 */
void cwe124_socket_bad(int s) {
  int data = readIndexSocket(s);
  int buffer[10] = {0};
  if (data < 10) {
    buffer[data] = 1; // $ Alert
  }
}

/* Juliet CWE194_Unexpected_Sign_Extension__fgets_memcpy_01 */
void cwe194_fgets_memcpy_bad() {
  short data = 0;
  char inputBuffer[14] = "";
  if (fgets(inputBuffer, 14, stdin) != 0) // $ Source
    data = (short)atoi(inputBuffer);
  {
    char source[100];
    char dest[100] = "";
    memset(source, 'A', 100 - 1);
    source[100 - 1] = '\0';
    if (data < 100) {
      memcpy(dest, source, data); // $ Alert
      dest[data] = '\0'; // $ Alert
    }
    printLine(dest);
  }
}

/* Safe: both bounds are checked. */
void both_bounds_good(int s) {
  int data = readIndexSocket(s);
  int buffer[10] = {0};
  if (data >= 0 && data < 10) {
    buffer[data] = 1;
  }
}

/* Safe: negative values are rejected earlier. */
void early_return_good(int s) {
  int data = readIndexSocket(s);
  int buffer[10] = {0};
  if (data < 0)
    return;
  if (data < 10) {
    buffer[data] = 1;
  }
}

/* Safe: the index is unsigned. */
void unsigned_good(int s) {
  unsigned int data = (unsigned int)readIndexSocket(s);
  int buffer[10] = {0};
  if (data < 10) {
    buffer[data] = 1;
  }
}

/* Safe: the value is not untrusted. */
void constant_good(int n) {
  int buffer[10] = {0};
  int data = n % 5;
  if (data < 10) {
    buffer[data] = 1;
  }
}

/* Not reported by this query: no bounds check at all. */
void no_check(int s) {
  int data = readIndexSocket(s);
  int buffer[10] = {0};
  buffer[data] = 1;
}
