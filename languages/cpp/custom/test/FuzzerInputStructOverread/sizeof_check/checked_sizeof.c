#include "../image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(struct Image))
    return 0;
  const struct Image *img = (const struct Image *)data;
  printf("%d %d %c\n", img->width, img->height, img->data[0]); // GOOD
  return 0;
}
