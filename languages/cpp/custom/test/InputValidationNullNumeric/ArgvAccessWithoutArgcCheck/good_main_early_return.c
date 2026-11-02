typedef struct _FILE FILE;
FILE *fopen(const char *path, const char *mode);
int printf(const char *fmt, ...);
void exit(int status);

static void usage(const char *prog) {
  printf("usage: %s <file>\n", prog);
  exit(1);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
  }
  FILE *fp = fopen(argv[1], "r");
  return fp != 0;
}
