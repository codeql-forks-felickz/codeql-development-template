typedef unsigned long size_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);

/*
 * Regression tests showing that the stock `cpp/overflow-buffer` query (in the
 * `security-extended` suite) reports these Juliet cases.
 */

/* Juliet CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_01: BAD */
void cwe131_bad() {
  int *data = NULL;
  data = (int *)malloc(10);
  if (data == NULL) exit(-1);
  {
    int source[10] = {0};
    memcpy(data, source, 10 * sizeof(int));
    free(data);
  }
}

/* GOOD: the allocation uses sizeof(int). */
void cwe131_good() {
  int *data = NULL;
  data = (int *)malloc(10 * sizeof(int));
  if (data == NULL) exit(-1);
  {
    int source[10] = {0};
    memcpy(data, source, 10 * sizeof(int));
    free(data);
  }
}

/* Juliet CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01: BAD */
void cwe805_bad() {
  char *data = NULL;
  data = (char *)malloc(50 * sizeof(char));
  if (data == NULL) exit(-1);
  data[0] = '\0';
  {
    char source[100];
    memset(source, 'C', 100 - 1);
    source[100 - 1] = '\0';
    memcpy(data, source, 100 * sizeof(char));
    data[100 - 1] = '\0';
    free(data);
  }
}

/* GOOD: the destination is as large as the copy. */
void cwe805_good() {
  char *data = NULL;
  data = (char *)malloc(100 * sizeof(char));
  if (data == NULL) exit(-1);
  data[0] = '\0';
  {
    char source[100];
    memset(source, 'C', 100 - 1);
    source[100 - 1] = '\0';
    memcpy(data, source, 100 * sizeof(char));
    data[100 - 1] = '\0';
    free(data);
  }
}
