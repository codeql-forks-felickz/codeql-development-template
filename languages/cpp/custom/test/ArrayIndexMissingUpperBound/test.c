typedef unsigned long size_t;
typedef long ssize_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
int atoi(const char *);
int printf(const char *, ...);
ssize_t recv(int, void *, size_t, int);

int readIndex(int s) {
  char inputBuffer[14];
  int data = -1;
  ssize_t r = recv(s, inputBuffer, 13, 0);
  if (r > 0) {
    inputBuffer[r] = '\0';
    data = atoi(inputBuffer);
  }
  return data;
}

/* Juliet CWE121 ..._CWE129_connect_socket_01 */
void bad_stack(int s) {
  int buffer[10] = {0};
  int data = readIndex(s);
  if (data >= 0) {
    buffer[data] = 1; // BAD: CWE-121
    printf("%d\n", buffer[0]);
  }
}

/* Juliet CWE122 ..._c_CWE129_connect_socket_01 */
void bad_heap(int s) {
  int data = readIndex(s);
  int *buffer = (int *)malloc(10 * sizeof(int));
  if (buffer == NULL) exit(-1);
  if (data >= 0) {
    buffer[data] = 1; // BAD: CWE-122
  }
  free(buffer);
}

void bad_read(int s) {
  int buffer[10] = {0};
  int data = readIndex(s);
  if (data < 0)
    return;
  printf("%d\n", buffer[data]); // BAD: out-of-bounds read
}

void good_bothBounds(int s) {
  int buffer[10] = {0};
  int data = readIndex(s);
  if (data >= 0 && data < 10) {
    buffer[data] = 1; // GOOD
  }
}

void good_upperBoundVariable(int s, int len) {
  int *buffer = (int *)malloc(len * sizeof(int));
  int data = readIndex(s);
  if (data >= 0 && data < len) {
    buffer[data] = 1; // GOOD
  }
  free(buffer);
}

void good_earlyReturn(int s) {
  int buffer[10] = {0};
  int data = readIndex(s);
  if (data < 0 || data > 9)
    return;
  buffer[data] = 1; // GOOD
}

void good_modulo(int s) {
  int buffer[10] = {0};
  int data = readIndex(s) % 10;
  if (data >= 0) {
    buffer[data] = 1; // GOOD: range analysis shows data < 10
  }
}

void good_constantSource() {
  int buffer[10] = {0};
  int data = 7;
  if (data >= 0) {
    buffer[data] = 1; // GOOD: not untrusted
  }
}

void unchecked(int s) {
  int buffer[10] = {0};
  int data = readIndex(s);
  buffer[data] = 1; // not reported: no bounds check at all (cpp/unclear-array-index-validation)
}
