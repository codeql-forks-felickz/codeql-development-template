typedef unsigned long size_t;
typedef struct _FILE FILE;
FILE *fopen(const char *path, const char *mode);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int fclose(FILE *stream);
int recv(int s, char *buf, int len, int flags);
int atoi(const char *s);
char *getenv(const char *name);
int printf(const char *fmt, ...);

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

// Pattern from an image parser: the height field is read from a file and
// used as a divisor without a zero check.
int process_image_bad(const char *filename) {
  FILE *fp = fopen(filename, "r");
  struct Image img;
  int total = 0;
  while (fread(&img, sizeof(img), 1, fp) > 0) { // $ Source
    int ratio = img.width / img.height; // $ Alert
    total += ratio;
  }
  fclose(fp);
  return total;
}

// Same pattern through a pointer to the struct.
int process_image_ptr_bad(FILE *fp) {
  struct Image img;
  struct Image *p = &img;
  fread(p, sizeof(img), 1, fp); // $ Source
  return p->width / p->height; // $ Alert
}

// Remainder operator and compound assignment.
int process_image_rem_bad(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp); // $ Source
  int x = img.width % img.height; // $ Alert
  int y = 1000;
  y /= img.height; // $ Alert
  return x + y;
}

// Juliet-style: an integer is received from a socket, converted with atoi and
// used as a divisor.
void socket_bad(int sock) {
  char input[16];
  int data = 0;
  if (recv(sock, input, sizeof(input) - 1, 0) > 0) { // $ Source
    data = atoi(input);
  }
  printf("%d\n", 100 / data); // $ Alert
}

void env_bad() {
  int n = atoi(getenv("COUNT")); // $ Source
  printf("%d\n", 100 % n); // $ Alert
}

// --- Safe counterparts: no alerts expected below ---

int process_image_good(const char *filename) {
  FILE *fp = fopen(filename, "r");
  struct Image img;
  int total = 0;
  while (fread(&img, sizeof(img), 1, fp) > 0) {
    if (img.height == 0)
      continue;
    total += img.width / img.height;
  }
  fclose(fp);
  return total;
}

int process_image_good2(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  if (img.height != 0) {
    return img.width / img.height;
  }
  return 0;
}

int process_image_good3(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  if (img.height <= 0)
    return -1;
  return img.width / img.height;
}

int process_image_good4(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  return img.height ? img.width / img.height : 0;
}

void socket_good(int sock) {
  char input[16];
  int data = 0;
  if (recv(sock, input, sizeof(input) - 1, 0) > 0) {
    data = atoi(input);
  }
  if (data != 0) {
    printf("%d\n", 100 / data);
  }
}

// Tainted value used as dividend, not as divisor.
void socket_dividend_good(int sock) {
  char input[16];
  recv(sock, input, sizeof(input) - 1, 0);
  int data = atoi(input);
  printf("%d\n", data / 7);
}

// Untainted divisor.
int constant_divisor_good(int a, int b) {
  return a / b;
}

// Floating point division does not trap on zero.
double float_good(FILE *fp) {
  double d;
  fread(&d, sizeof(d), 1, fp);
  return 1.0 / d;
}

// Divisor made non-zero by arithmetic.
void socket_plus_one_good(int sock) {
  char input[16];
  recv(sock, input, sizeof(input) - 1, 0);
  unsigned int data = (unsigned int)atoi(input) % 10u;
  printf("%u\n", 100u / (data + 1u));
}

// The field is overwritten with a constant before the division.
int process_image_overwrite_good(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  img.height = 4;
  return img.width / img.height;
}
