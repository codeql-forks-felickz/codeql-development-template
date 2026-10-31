typedef unsigned long size_t;
typedef struct FILE FILE;
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

/* Broken-Vulnerable-Code-Snippets damnvuln.c */
void process_image(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp); // $ Source
  int size3 = img.width / img.height;
  char buff3[10];
  buff3[size3 + 100] = 'c'; // $ Alert
  buff3[size3] = 'c'; // $ Alert
}

/* Safe: the index is checked. */
void checked(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int i = img.width;
  char buf[10];
  if (i >= 0 && i < 10)
    buf[i] = 'c';
}

/* Safe: the index is reduced modulo the array size. */
void masked(FILE *fp) {
  unsigned int i;
  fread(&i, sizeof(i), 1, fp);
  char buf[16];
  buf[i % 16] = 'c';
}

/* An untrusted range can exceed the actual array size. */
void masked_too_wide(FILE *fp) {
  unsigned int i;
  fread(&i, sizeof(i), 1, fp); // $ Source
  char buf[16];
  buf[i % 32] = 'c'; // $ Alert
}

/* A tainted unsigned byte can be larger than a small array. */
void unsigned_char_index(FILE *fp) {
  unsigned char i;
  fread(&i, sizeof(i), 1, fp); // $ Source
  char buf[16];
  buf[i] = 'c'; // $ Alert
}

/* Negative values remain possible through signed modulo. */
void signed_masked(FILE *fp) {
  int i;
  fread(&i, sizeof(i), 1, fp); // $ Source
  char buf[16];
  buf[i % 16] = 'c'; // $ Alert
}

/* A previous value's check does not apply after reassignment. */
void reassigned_bad(FILE *fp) {
  unsigned int i;
  fread(&i, sizeof(i), 1, fp); // $ Source
  char buf[16];
  if (i < 16) {
    fread(&i, sizeof(i), 1, fp); // $ Source
    buf[i] = 'c'; // $ Alert
  }
}

/* Safe: the index is not untrusted. */
void constant_loop(void) {
  char buf[10];
  for (int i = 0; i < 10; i++)
    buf[i] = 'c';
}
