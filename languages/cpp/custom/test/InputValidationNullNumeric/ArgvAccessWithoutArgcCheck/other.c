int printf(const char *fmt, ...);

// Not main: argv-like parameters of other functions are out of scope.
int helper(int argc, char **argv) {
  printf("%s\n", argv[1]);
  return 0;
}
