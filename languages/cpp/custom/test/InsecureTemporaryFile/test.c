typedef unsigned long size_t;
typedef struct _FILE FILE;
#define NULL ((void *)0)

#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_EXCL 0200
#define O_TRUNC 01000
#define S_IREAD 0400
#define S_IWRITE 0200

char *tmpnam(char *s);
char *tmpnam_r(char *s);
char *tempnam(const char *dir, const char *pfx);
char *mktemp(char *tmpl);
int mkstemp(char *tmpl);
int open(const char *path, int flags, ...);
int openat(int dirfd, const char *path, int flags, ...);
int creat(const char *path, int mode);
FILE *fopen(const char *path, const char *mode);
int close(int fd);
int fclose(FILE *f);
void exit(int status);
void printLine(const char *line);

/* tmpnam() name opened with O_CREAT but without O_EXCL. */
void bad_tmpnam_open(void) {
  char *filename;
  int fd;
  filename = tmpnam(NULL); // $ Source
  if (filename == NULL) {
    exit(1);
  }
  printLine(filename);
  fd = open(filename, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

/* mktemp() name opened with O_CREAT but without O_EXCL. */
void bad_mktemp_open(void) {
  char *filename;
  char tmpl[] = "fnXXXXXX";
  int fd;
  filename = mktemp(tmpl); // $ Source
  if (filename == NULL) {
    exit(1);
  }
  fd = open(filename, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

/* mktemp() modifies its template in place; the template buffer is then opened. */
void bad_mktemp_inplace(void) {
  char tmpl[] = "/tmp/fnXXXXXX";
  int fd;
  mktemp(tmpl); // $ Source
  fd = open(tmpl, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

/* tmpnam() writing into a caller-provided buffer. */
void bad_tmpnam_buffer(void) {
  char buf[64];
  int fd;
  tmpnam(buf); // $ Source
  fd = open(buf, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

void bad_tmpnam_r_openat(int dirfd) {
  char buf[64];
  int fd;
  if (tmpnam_r(buf) == NULL) { // $ Source
    return;
  }
  fd = openat(dirfd, buf, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

void bad_tempnam_creat(void) {
  char *filename = tempnam("/tmp", "pfx"); // $ Source
  int fd = creat(filename, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

void bad_tmpnam_fopen(void) {
  char *filename = tmpnam(NULL); // $ Source
  FILE *f = fopen(filename, "w+"); // $ Alert
  if (f != NULL) {
    fclose(f);
  }
}

static void open_helper(const char *path) {
  int fd = open(path, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // $ Alert
  if (fd != -1) {
    close(fd);
  }
}

void bad_tmpnam_interprocedural(void) {
  char *filename = tmpnam(NULL); // $ Source
  open_helper(filename);
}

/* GOOD: mkstemp() creates and opens the file atomically. */
void good_mkstemp(void) {
  char filename[] = "/tmp/fileXXXXXX";
  int fd = mkstemp(filename);
  printLine(filename);
  if (fd != -1) {
    close(fd);
  }
}

/* GOOD: O_EXCL makes open() fail if the path already exists. */
void good_tmpnam_excl(void) {
  char *filename = tmpnam(NULL);
  int fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IREAD | S_IWRITE);
  if (fd != -1) {
    close(fd);
  }
}

/* GOOD: fopen with the C11 exclusive "x" mode. */
void good_tmpnam_fopen_exclusive(void) {
  char *filename = tmpnam(NULL);
  FILE *f = fopen(filename, "wx");
  if (f != NULL) {
    fclose(f);
  }
}

/* GOOD: the file is not created by this call. */
void good_tmpnam_read_only(void) {
  char *filename = tmpnam(NULL);
  int fd = open(filename, O_RDONLY);
  if (fd != -1) {
    close(fd);
  }
}

/* GOOD: the path does not come from a predictable temporary-name generator. */
void good_fixed_path(const char *path) {
  int fd = open(path, O_RDWR | O_CREAT, S_IREAD | S_IWRITE);
  if (fd != -1) {
    close(fd);
  }
}
