typedef unsigned long size_t;
typedef long ssize_t;
typedef struct FILE FILE;

size_t fread(void *, size_t, size_t, FILE *);
ssize_t read(int, void *, size_t);
int printf(const char *, ...);

struct Image {
  char header[8];
  char data[16];
};

void printImage(FILE *file) {
  struct Image image;
  fread(&image, sizeof(image), 1, file); // $ Source
  printf("%s %s", image.header, image.data); // $ Alert, $ Alert
  printf("%.*s", (int)sizeof(image.header), image.header); // GOOD
}

void printReadBuffer(int fd) {
  char buffer[1024] = {0};
  read(fd, buffer, sizeof(buffer)); // $ Source
  printf("%s", buffer); // $ Alert
  printf("%.*s", (int)sizeof(buffer), buffer); // GOOD
}
