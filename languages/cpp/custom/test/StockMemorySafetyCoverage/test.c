typedef unsigned long size_t;
typedef long ssize_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
int printf(const char *, ...);
size_t strlen(const char *);
ssize_t recv(int, void *, size_t, int);

/* Juliet CWE134_Uncontrolled_Format_String__char_connect_socket_printf_01 */
void cwe134_bad(int s) {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  ssize_t r = recv(s, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0);
  if (r > 0)
    data[dataLen + r] = '\0';
  printf(data); // BAD: reported by cpp/tainted-format-string
}

void cwe134_good(int s) {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  ssize_t r = recv(s, data, 99, 0);
  if (r > 0)
    data[r] = '\0';
  printf("%s\n", data); // GOOD
}

/* Juliet CWE415_Double_Free__malloc_free_char_01 */
void cwe415_bad() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  free(data);
  free(data); // BAD: reported by cpp/double-free
}

void cwe415_good() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  free(data);
  data = NULL;
  free(data); // GOOD
}
