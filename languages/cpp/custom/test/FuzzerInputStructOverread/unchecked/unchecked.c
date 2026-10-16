#include "../image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct Image *img = (struct Image *)data;
  return img->width; // BAD: input size never checked
}
