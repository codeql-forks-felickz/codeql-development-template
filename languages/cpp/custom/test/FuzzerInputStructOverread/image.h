typedef unsigned long size_t;
typedef unsigned char uint8_t;
void *malloc(size_t);
void free(void *);
void *memcpy(void *, const void *, size_t);
int printf(const char *, ...);

struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};
