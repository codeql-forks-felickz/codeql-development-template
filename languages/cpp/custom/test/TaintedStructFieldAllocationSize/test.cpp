typedef unsigned long size_t;
typedef struct FILE FILE;

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
void *malloc(size_t size);

struct Image {
  int width;
};

void mayModify(Image &img);
void observe(const Image &img);

void process_nonconst_reference(FILE *fp) {
  Image img;
  fread(&img, sizeof(img), 1, fp); // $ Source
  img.width = 16;
  mayModify(img);
  void *buf = malloc(img.width * 2); // $ Alert
}

void process_const_reference(FILE *fp) {
  Image img;
  fread(&img, sizeof(img), 1, fp);
  img.width = 16;
  observe(img);
  void *buf = malloc(img.width * 2);
}
