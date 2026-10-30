typedef unsigned long size_t;
typedef struct FILE FILE;
typedef long ssize_t;

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
void *malloc(size_t size);
void free(void *ptr);
void *memcpy(void *dest, const void *src, size_t n);
char *getenv(const char *name);
int atoi(const char *s);

#define MAX_DIM 1024

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

struct Dims {
  int width;
  int height;
};

struct Packet {
  int type;
  struct Dims dims;
};

struct Config {
  int a;
  int b;
};

// Reduced from the linked finding: struct filled by fread, fields used in signed
// arithmetic that can underflow (CWE-191) or overflow (CWE-190), then allocated.
void process_image(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) { // $ Source
    int size1 = img.width + img.height;
    char *buff1 = (char *)malloc(size1); // $ Alert
    free(buff1);

    int size2 = img.width - img.height + 100;
    char *buff2 = (char *)malloc(size2); // $ Alert
    memcpy(buff2, img.data, sizeof(img.data));
    free(buff2);
  }
}

// Struct accessed through a pointer.
void process_image_ptr(FILE *fp, struct Image *p) {
  fread(p, sizeof(*p), 1, fp); // $ Source
  char *buf = (char *)malloc(p->width - p->height); // $ Alert
  free(buf);
}

// Network header read with recv, nested struct field.
void process_packet(int sock) {
  struct Packet pkt;
  recv(sock, &pkt, sizeof(pkt), 0); // $ Source
  char *buf = (char *)malloc(pkt.dims.width * pkt.dims.height); // $ Alert
  free(buf);
}

// GOOD: fields are range checked before use.
void process_image_checked(FILE *fp) {
  struct Image img;
  if (fread(&img, sizeof(img), 1, fp) != 1)
    return;
  if (img.width < 0 || img.height < 0 || img.width > MAX_DIM || img.height > MAX_DIM || img.width < img.height)
    return;
  char *buf = (char *)malloc(img.width - img.height + 100);
  free(buf);
}

// GOOD: the computed size is range checked before use.
void process_image_size_checked(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int size = img.width - img.height;
  if (size < 0 || size > MAX_DIM)
    return;
  char *buf = (char *)malloc(size);
  free(buf);
}

// GOOD: masked value cannot overflow.
void process_image_masked(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  char *buf = (char *)malloc((img.width & 0xff) + 1);
  free(buf);
}

// GOOD: struct is not attacker controlled.
void process_local_image(void) {
  struct Image img;
  img.width = 10;
  img.height = 5;
  char *buf = (char *)malloc(img.width - img.height);
  free(buf);
}

// GOOD: only field `a` is tainted, field `b` is not. The flow through `a` is
// already reported by the stock `cpp/uncontrolled-allocation-size` query, so it
// is not reported again here.
void process_config(void) {
  struct Config cfg;
  cfg.a = atoi(getenv("CFG_A"));
  cfg.b = 16;
  char *buf1 = (char *)malloc(cfg.b * 2);
  char *buf2 = (char *)malloc(cfg.a * 2);
  free(buf1);
  free(buf2);
}

// Struct passed to a helper that computes the size.
static int area(struct Image *p) { return p->width * p->height; }

void process_image_helper(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp); // $ Source
  char *buf = (char *)malloc(area(&img)); // $ Alert
  free(buf);
}

// Struct copied from a received buffer.
void process_copied_header(int sock) {
  char raw[64];
  struct Image img;
  recv(sock, raw, sizeof(raw), 0); // $ Source
  memcpy(&img, raw, sizeof(img));
  char *buf = (char *)malloc(img.width - img.height); // $ Alert
  free(buf);
}

// Field assigned before the struct is (re)filled from input.
void process_image_refilled(FILE *fp) {
  struct Image img;
  img.width = 16;
  fread(&img, sizeof(img), 1, fp); // $ Source
  char *buf = (char *)malloc(img.width * 2); // $ Alert
  free(buf);
}

// GOOD: fields are overwritten with trusted values after the read.
void process_image_overwritten(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  img.width = 16;
  img.height = 8;
  char *buf = (char *)malloc(img.width - img.height);
  free(buf);
}

static struct Image table[4];

// GOOD: a trusted struct selected by an untrusted index is not itself filled from input.
void process_table_entry(void) {
  int i = atoi(getenv("IDX"));
  char *buf1 = (char *)malloc(table[i].width - table[i].height);
  struct Image *p = &table[i];
  char *buf2 = (char *)malloc(p->width * 2);
  free(buf1);
  free(buf2);
}

// Field reassigned in place from attacker-controlled values.
void process_image_normalized(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp); // $ Source
  img.width = img.width * img.height;
  char *buf1 = (char *)malloc(img.width * 4); // $ Alert
  img.height += 1;
  char *buf2 = (char *)malloc(img.height * 4); // $ Alert
  img.width = img.height;
  char *buf3 = (char *)malloc(img.width - 8); // $ Alert
  free(buf1);
  free(buf2);
  free(buf3);
}

// GOOD: checks on the same nested field paths suppress the report.
void process_checked_nested_packet(int sock) {
  struct Packet pkt;
  recv(sock, &pkt, sizeof(pkt), 0);
  if (pkt.dims.width < 0 || pkt.dims.height < 0 || pkt.dims.width > MAX_DIM ||
      pkt.dims.height > MAX_DIM)
    return;
  char *buf = (char *)malloc((size_t)pkt.dims.width * pkt.dims.height);
  free(buf);
}

// BAD: checking another instance does not validate the received packet.
void process_other_checked_packet(int sock) {
  struct Packet pkt, other;
  recv(sock, &pkt, sizeof(pkt), 0); // $ Source
  if (other.dims.width > MAX_DIM || other.dims.height > MAX_DIM)
    return;
  char *buf = (char *)malloc(pkt.dims.width - pkt.dims.height); // $ Alert
  free(buf);
}

static void consume(int value) {}

// GOOD: passing a scalar field to a call does not refill the whole object.
void process_scalar_call_after_overwrite(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  img.width = 16;
  consume(img.height);
  char *buf = (char *)malloc(img.width * 2);
  free(buf);
}
