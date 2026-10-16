// Minimal reproductions of Juliet CWE-23 / CWE-36 test cases using console input
// (fgets from stdin) and std::ofstream sinks.
typedef unsigned long size_t;
typedef struct FILE FILE;
extern FILE *stdin;
struct sockaddr { int sa_family; };

extern "C" {
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *stream);
char *fgets(char *s, int size, FILE *stream);
size_t strlen(const char *s);
int socket(int domain, int type, int protocol);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, void *addrlen);
long recv(int sockfd, void *buf, size_t len, int flags);
}

namespace std {
template <class charT> struct char_traits {};
template <class charT, class traits = char_traits<charT> >
class basic_ofstream {
public:
  basic_ofstream();
  explicit basic_ofstream(const char *filename);
  void open(const char *filename);
  void close();
};
typedef basic_ofstream<char> ofstream;
} // namespace std

#define FILENAME_MAX 4096
#define BASEPATH "/tmp/"

// CWE23_Relative_Path_Traversal__char_console_fopen_01
void bad_console_fopen(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  if (FILENAME_MAX - dataLen > 1) {
    if (fgets(data + dataLen, (int)(FILENAME_MAX - dataLen), stdin) != 0) { // $ Source
      dataLen = strlen(data);
      if (dataLen > 0 && data[dataLen - 1] == '\n') {
        data[dataLen - 1] = '\0';
      }
    } else {
      data[dataLen] = '\0';
    }
  }
  {
    FILE *pFile = fopen(data, "wb+"); // $ Alert
    if (pFile != 0) fclose(pFile);
  }
}

// CWE36_Absolute_Path_Traversal__char_console_fopen_01 (no base directory at all)
void bad_console_fopen_absolute(void) {
  char dataBuffer[FILENAME_MAX] = "";
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  if (FILENAME_MAX - dataLen > 1) {
    if (fgets(data + dataLen, (int)(FILENAME_MAX - dataLen), stdin) != 0) { // $ Source
      dataLen = strlen(data);
      if (dataLen > 0 && data[dataLen - 1] == '\n') {
        data[dataLen - 1] = '\0';
      }
    }
  }
  {
    FILE *pFile = fopen(data, "wb+"); // $ Alert
    if (pFile != 0) fclose(pFile);
  }
}

// CWE23_Relative_Path_Traversal__char_listen_socket_ofstream_01
void bad_listen_socket_ofstream(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  int acceptSocket = accept(socket(2, 1, 6), 0, 0);
  size_t dataLen = strlen(data);
  long recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  {
    std::ofstream outputFile;
    outputFile.open((char *)data); // $ Alert
    outputFile.close();
  }
}

// ofstream constructor taking the tainted path.
void bad_listen_socket_ofstream_ctor(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  int acceptSocket = accept(socket(2, 1, 6), 0, 0);
  size_t dataLen = strlen(data);
  long recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  std::ofstream outputFile(data); // $ Alert
  outputFile.close();
}

// goodG2B: fixed file names, so no alert is expected.
void good_console_fixed(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH "file.txt";
  FILE *pFile = fopen(dataBuffer, "wb+");
  if (pFile != 0) fclose(pFile);
  std::ofstream outputFile;
  outputFile.open(dataBuffer);
  outputFile.close();
}
