int printf(const char *fmt, ...);

// argc is only checked after argv[1] has already been read.
int main(int argc, char **argv) {
  char *file = argv[1]; // $ Alert
  if (argc < 2)
    return 1;
  printf("%s\n", file);
  return 0;
}
