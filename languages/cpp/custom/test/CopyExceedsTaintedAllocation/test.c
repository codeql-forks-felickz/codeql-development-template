typedef unsigned long size_t;
typedef struct FILE FILE;
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
void *malloc(size_t size);
void free(void *ptr);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

/* Damn_Vulnerable_C_Program dvcp.c: sizes derived from file contents. */
void process_image(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) { // $ Source
    int size2 = img.width - img.height + 100;
    char *buff2 = (char *)malloc(size2); // $ Sink
    memcpy(buff2, img.data, sizeof(img.data)); // $ Alert

    int size3 = img.width / img.height;
    char *buff4 = (char *)malloc(size3); // $ Sink
    memcpy(buff4, img.data, sizeof(img.data)); // $ Alert

    free(buff2);
    free(buff4);
  }
}

void unchecked_memset(FILE *fp) {
  int len;
  fread(&len, sizeof(len), 1, fp); // $ Source
  char *p = (char *)malloc(len); // $ Sink
  memset(p, 0, 16); // $ Alert
  free(p);
}

/* Safe: the size is checked before the copy. */
void checked_before_copy(FILE *fp) {
  struct Image img;
  if (fread(&img, sizeof(img), 1, fp) > 0) {
    int size = img.width / img.height;
    if (size < 10)
      return;
    char *buf = (char *)malloc(size);
    memcpy(buf, img.data, sizeof(img.data));
    free(buf);
  }
}

/* Safe: the size is checked around the copy. */
void checked_at_copy(FILE *fp) {
  struct Image img;
  if (fread(&img, sizeof(img), 1, fp) > 0) {
    int size = img.width - img.height;
    char *buf = (char *)malloc(size);
    if (buf && size >= 10)
      memcpy(buf, img.data, sizeof(img.data));
    free(buf);
  }
}

/* Safe: the allocation always has room for the copy. */
void padded_allocation(FILE *fp) {
  unsigned int extra;
  fread(&extra, sizeof(extra), 1, fp);
  char *buf = (char *)malloc(extra % 100 + 10);
  memset(buf, 0, 10);
  free(buf);
}

/* Safe: the allocation size is not untrusted. */
void constant_allocation(void) {
  char src[10] = {0};
  char *buf = (char *)malloc(sizeof(src));
  memcpy(buf, src, sizeof(src));
  free(buf);
}

/* Safe: the copy length is the allocation size. */
void copy_matches_allocation(FILE *fp, const char *src) {
  int n;
  fread(&n, sizeof(n), 1, fp);
  char *buf = (char *)malloc(n);
  memcpy(buf, src, n);
  free(buf);
}
