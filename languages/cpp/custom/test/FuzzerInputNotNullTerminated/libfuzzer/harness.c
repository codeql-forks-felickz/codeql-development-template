#include "../decls.h"

void parse(const char *s) { printf("%d\n", atoi(s)); } // BAD (reached from data)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char copy[256];
  size_t n = strnlen((const char *)data, size); // GOOD: bounded
  if (size == 0 || size >= sizeof(copy))
    return 0;
  memcpy(copy, data, size);
  copy[size] = '\0';
  strlen(copy);                 // GOOD: null-terminated copy
  printf((const char *)data);   // BAD
  parse((const char *)data + 1); // flows to atoi in parse
  return (int)strlen((const char *)data); // BAD
}
