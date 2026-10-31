typedef unsigned long size_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void *memset(void *, int, size_t);
void *alloca(size_t);
void printLine(const char *);

/* Juliet CWE590_Free_Memory_Not_on_Heap__free_char_declare_01 */
void cwe590_declare_bad() {
  char *data;
  data = NULL;
  {
    char dataBuffer[100];
    memset(dataBuffer, 'A', 100 - 1);
    dataBuffer[100 - 1] = '\0';
    data = dataBuffer; // $ Source
  }
  printLine(data);
  free(data); // $ Alert
}

/* Juliet CWE590_Free_Memory_Not_on_Heap__free_char_static_01 */
void cwe590_static_bad() {
  char *data = NULL;
  {
    static char dataBuffer[100];
    data = dataBuffer; // $ Source
  }
  free(data); // $ Alert
}

/* Juliet CWE590_Free_Memory_Not_on_Heap__free_char_alloca_01 */
void cwe590_alloca_bad() {
  char *data = (char *)alloca(100 * sizeof(char)); // $ Source
  free(data); // $ Alert
}

static void release(char *p) { free(p); } // $ Alert

void interprocedural_bad() {
  char buf[16];
  release(buf); // $ Source
}

/* Safe: heap memory is freed. */
void cwe590_good() {
  char *data = NULL;
  {
    char *dataBuffer = (char *)malloc(100 * sizeof(char));
    if (dataBuffer == NULL) return;
    data = dataBuffer;
  }
  free(data);
}

/* Safe: the pointer is reassigned to heap memory before it is freed. */
void reassigned_good() {
  char buf[16];
  char *p = buf;
  p = (char *)malloc(16);
  free(p);
}
