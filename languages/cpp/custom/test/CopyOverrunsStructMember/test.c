typedef unsigned long size_t;
#define NULL ((void *)0)
void *malloc(size_t);
void free(void *);
void exit(int);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);

#define SRC_STR "0123456789abcdef0123456789abcde"

typedef struct _charVoid {
  char charFirst[16];
  void *voidSecond;
  void *voidThird;
} charVoid;

typedef struct _header {
  int length;
  char data[1];
} header;

/* Juliet CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01 */
void cwe121_bad() {
  charVoid structCharVoid;
  structCharVoid.voidSecond = (void *)SRC_STR;
  memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid)); // $ Alert
  structCharVoid.charFirst[(sizeof(structCharVoid.charFirst) / sizeof(char)) - 1] = '\0';
}

/* Juliet CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01 */
void cwe122_bad() {
  charVoid *structCharVoid = (charVoid *)malloc(sizeof(charVoid));
  if (structCharVoid == NULL) exit(-1);
  structCharVoid->voidSecond = (void *)SRC_STR;
  memcpy(structCharVoid->charFirst, SRC_STR, sizeof(*structCharVoid)); // $ Alert
  free(structCharVoid);
}

void memset_bad() {
  charVoid s;
  memset(s.charFirst, 0, 24); // $ Alert
}

/* Safe: the size of the member is used. */
void cwe121_good() {
  charVoid structCharVoid;
  memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid.charFirst));
}

/* Safe: the whole structure is the destination. */
void whole_struct_good() {
  charVoid s;
  memset(&s, 0, sizeof(s));
}

/* Safe: a trailing one-element array is a variable-size member. */
void flexible_good(header *h) {
  memcpy(h->data, SRC_STR, 20);
}
