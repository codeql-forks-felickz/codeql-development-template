typedef unsigned long size_t;
typedef struct _FILE FILE;
FILE *fopen(const char *, const char *);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
void *malloc(size_t);
void free(void *);
void *memcpy(void *, const void *, size_t);

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

/* Dimensions read from a file are added in signed arithmetic and used as an allocation size. */
void process_image(const char *filename) {
  FILE *fp = fopen(filename, "r");
  struct Image img;
  if (fp == 0)
    return;
  while (fread(&img, sizeof(img), 1, fp) > 0) { // $ Source
    int size1 = img.width + img.height;
    char *buff1 = (char *)malloc(size1); // $ Alert
    memcpy(buff1, img.data, sizeof(img.data));
    free(buff1);

    int size2 = img.width - img.height + 100;
    char *buff2 = (char *)malloc(size2); // $ Alert
    free(buff2);
  }
}

/* Same pattern through a pointer to the struct. */
void process_image_ptr(FILE *fp, struct Image *pimg) {
  fread(pimg, sizeof(*pimg), 1, fp); // $ Source
  char *buf = (char *)malloc(pimg->width * pimg->height); // $ Alert
  free(buf);
}

/* SAFE: the struct is not read from external input. */
void constant_image(void) {
  struct Image img;
  img.width = 16;
  img.height = 16;
  char *buf = (char *)malloc(img.width + img.height);
  free(buf);
}

/* SAFE: the dimensions are copied to locals and upper-bounds checked. */
void checked_locals(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int w = img.width;
  int h = img.height;
  if (w < 0 || w > 1024 || h < 0 || h > 1024)
    return;
  char *buf = (char *)malloc(w + h);
  free(buf);
}

/* SAFE: the fields are upper-bounds checked before use. */
void checked_fields(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  if (img.width < 0 || img.width > 1024 || img.height < 0 || img.height > 1024)
    return;
  char *buf = (char *)malloc(img.width + img.height);
  free(buf);
}

/* SAFE: the result is reduced by a remainder operation. */
void bounded_by_remainder(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  char *buf = (char *)malloc(((size_t)img.width + (size_t)img.height) % 4096);
  free(buf);
}

/* Not reported here: a scalar read is already covered by cpp/uncontrolled-allocation-size. */
void scalar_read(FILE *fp) {
  int w;
  fread(&w, sizeof(w), 1, fp);
  char *buf = (char *)malloc(w + 4);
  free(buf);
}
