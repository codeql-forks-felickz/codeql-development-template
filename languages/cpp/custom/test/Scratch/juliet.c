typedef unsigned long size_t;
typedef long ssize_t;
#define NULL ((void*)0)
void *malloc(size_t);
void free(void *);
void exit(int);
int atoi(const char *);
int printf(const char *, ...);
size_t strlen(const char *);
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
char *strchr(const char *, int);
ssize_t recv(int, void *, size_t, int);
int socket(int, int, int);

void printLine(const char *line) { if (line != NULL) printf("%s\n", line); }
void printIntLine(int i) { printf("%d\n", i); }

void cwe121_bad(int s) {
  int data = -1;
  char inputBuffer[14];
  int r = recv(s, inputBuffer, 13, 0);
  if (r > 0) { inputBuffer[r] = '\0'; data = atoi(inputBuffer); }
  int buffer[10] = {0};
  if (data >= 0) {
    buffer[data] = 1;
    printIntLine(buffer[0]);
  }
}

void cwe122_bad(int s) {
  int data = -1;
  char inputBuffer[14];
  int r = recv(s, inputBuffer, 13, 0);
  if (r > 0) { inputBuffer[r] = '\0'; data = atoi(inputBuffer); }
  int *buffer = (int *)malloc(10 * sizeof(int));
  if (buffer == NULL) exit(-1);
  if (data >= 0) {
    buffer[data] = 1;
    printIntLine(buffer[0]);
  }
  free(buffer);
}

void cwe134_bad(int s) {
  char *data;
  char dataBuffer[100] = "";
  data = dataBuffer;
  size_t dataLen = strlen(data);
  int r = recv(s, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0);
  if (r > 0) data[dataLen + r] = '\0';
  printf(data);
}

void cwe415_bad() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  free(data);
  free(data);
}

void cwe416_bad() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  memset(data, 'A', 100 - 1);
  data[100 - 1] = '\0';
  free(data);
  printLine(data);
}
