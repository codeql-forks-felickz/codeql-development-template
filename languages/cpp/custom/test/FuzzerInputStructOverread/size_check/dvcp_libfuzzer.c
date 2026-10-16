#include "../image.h"

/* Damn_Vulnerable_C_Program linux/imgRead_libfuzzer.c */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 12) {
    return 0;
  }
  struct Image *img;
  img = (struct Image *)data;
  int size1 = img->width + img->height; // GOOD: bytes 4..12 are within the checked 13 bytes
  char *buff1 = (char *)malloc(size1);
  memcpy(buff1, img->data, sizeof(img->data)); // BAD: data spans bytes 12..22
  free(buff1);
  return 0;
}
