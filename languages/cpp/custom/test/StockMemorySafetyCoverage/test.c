typedef unsigned long size_t;
typedef long ssize_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
int printf(const char *, ...);
size_t strlen(const char *);
ssize_t recv(int, void *, size_t, int);
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
size_t fread(void *, size_t, size_t, FILE *);

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

/* Juliet CWE134_Uncontrolled_Format_String__char_console_printf_01 */
void cwe134_console_bad() {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  if (100 - dataLen > 1) {
    if (fgets(data + dataLen, (int)(100 - dataLen), stdin) != NULL) {
      dataLen = strlen(data);
      if (dataLen > 0 && data[dataLen - 1] == '\n')
        data[dataLen - 1] = '\0';
    }
  }
  printf(data); // BAD: reported by cpp/tainted-format-string
}

/* Damn_Vulnerable_C_Program imgRead.c: conditional double free and use after free in a read loop */
struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

void dvcp_free_in_loop(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) {
    int size1 = img.width + img.height;
    char *buff1 = (char *)malloc(size1);
    free(buff1);
    if (size1 % 2 == 0) {
      free(buff1); // BAD: reported by cpp/double-free
    } else {
      if (size1 % 3 == 0) {
        buff1[0] = 'a'; // BAD: reported by cpp/use-after-free
      }
    }
  }
}
