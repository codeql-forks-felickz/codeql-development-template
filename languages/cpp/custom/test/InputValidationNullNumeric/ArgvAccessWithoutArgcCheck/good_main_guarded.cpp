int printf(const char *fmt, ...);

int main(int argc, char **argv) {
  if (argc >= 3) {
    printf("%s %s\n", argv[1], argv[2]);
  }
  const char *name = argc > 1 ? argv[1] : "default";
  printf("%s\n", name);
  for (int i = 1; i < argc; i++) {
    printf("%s\n", argv[i]);
  }
  return 0;
}
