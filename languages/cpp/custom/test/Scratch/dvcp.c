typedef unsigned long size_t;
typedef unsigned char uint8_t;
void *malloc(size_t);
void free(void *);
int printf(const char *, ...);
size_t strlen(const char *);
void *memcpy(void *, const void *, size_t);

struct Image { char header[4]; int width; int height; char data[10]; };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 12) return 0;
  struct Image *img = (struct Image *)data;
  char *b = (char *)malloc(10);
  memcpy(b, img->data, sizeof(img->data));
  free(b);
  return img->width;
}

unsigned char *__afl_fuzz_ptr;
unsigned int *__afl_fuzz_len;
#define __AFL_FUZZ_TESTCASE_BUF __afl_fuzz_ptr
#define __AFL_FUZZ_TESTCASE_LEN (*__afl_fuzz_len)

int ProcessImage() {
  unsigned char *shmem_buf = __AFL_FUZZ_TESTCASE_BUF;
  int bufsize = strlen((char *)shmem_buf);
  if (bufsize <= 12) return 0;
  printf("input: %s\n", shmem_buf);
  return 0;
}
