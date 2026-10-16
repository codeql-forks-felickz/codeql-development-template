typedef unsigned long size_t;
typedef long ssize_t;
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
ssize_t recv(int, void *, size_t, int);
int atoi(const char *);
void *malloc(size_t);
void free(void *);
void exit(int);

int readSocket(int s) {
  char inputBuffer[14];
  int data = -1;
  ssize_t r = recv(s, inputBuffer, 13, 0); // $ Source
  if (r > 0) {
    inputBuffer[r] = '\0';
    data = atoi(inputBuffer);
  }
  return data;
}

/* Juliet CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fgets_01 */
void cwe680_fgets_bad() {
  int data = -1;
  char inputBuffer[14] = "";
  if (fgets(inputBuffer, 14, stdin) != 0) // $ Source
    data = atoi(inputBuffer);
  {
    size_t i;
    int *intPointer = (int *)malloc(data * sizeof(int)); // $ Alert
    if (intPointer == 0) exit(-1);
    for (i = 0; i < (size_t)data; i++)
      intPointer[i] = 0;
    free(intPointer);
  }
}

/* Juliet CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_listen_socket_01 */
void cwe680_socket_bad(int s) {
  int data = readSocket(s);
  size_t i;
  int *intPointer = (int *)malloc(data * sizeof(int)); // $ Alert
  if (intPointer == 0) exit(-1);
  for (i = 0; i < (size_t)data; i++)
    intPointer[i] = 0;
  free(intPointer);
}

/* Safe: the value is range checked before the allocation. */
void checked_good(int s) {
  int data = readSocket(s);
  size_t i;
  if (data > 0 && data < 1000) {
    int *intPointer = (int *)malloc(data * sizeof(int));
    if (intPointer == 0) exit(-1);
    for (i = 0; i < (size_t)data; i++)
      intPointer[i] = 0;
    free(intPointer);
  }
}

/* Safe: the factor is small by construction. */
void bounded_good(int s) {
  unsigned int data = (unsigned int)readSocket(s) & 0xffu;
  int *intPointer = (int *)malloc(data * sizeof(int));
  free(intPointer);
}

/* Safe: the size does not involve a multiplication. */
void no_multiplication(int s) {
  int data = readSocket(s);
  char *p = (char *)malloc(data);
  free(p);
}
