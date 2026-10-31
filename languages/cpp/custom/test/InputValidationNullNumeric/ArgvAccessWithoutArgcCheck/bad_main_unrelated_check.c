int printf(const char *fmt, ...);

// The check on argc guards a different access only.
int main(int argc, char **argv) {
  if (argc > 2) {
    printf("%s\n", argv[2]);
  }
  printf("%s\n", argv[1]); // $ Alert
  return 0;
}
