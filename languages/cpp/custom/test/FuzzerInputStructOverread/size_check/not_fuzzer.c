#include "../image.h"

int parseImage(const uint8_t *data, size_t size) {
  struct Image *img = (struct Image *)data;
  return img->width; // not reported: not a fuzzing entry point
}
