typedef struct _FILE FILE;
FILE *fopen(const char *path, const char *mode);
int printf(const char *fmt, ...);

int ProcessImage(char *filename) {
  FILE *fp = fopen(filename, "r");
  return fp != 0;
}

// argv[1] is used without checking argc: running the program without
// arguments passes NULL to ProcessImage/fopen.
int main(int argc, char **argv) {
  ProcessImage(argv[1]); // $ Alert
  printf("%s\n", *(argv + 2)); // $ Alert
  printf("%s\n", argv[0]);
  return 0;
}
