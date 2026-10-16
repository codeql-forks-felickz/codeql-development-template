// Minimal reproductions of Juliet CWE-23 (Relative Path Traversal) test cases
// where TCP-supplied text is appended to a base directory and opened with fopen.
typedef unsigned long size_t;
typedef struct FILE FILE;
struct sockaddr { int sa_family; };

FILE *fopen(const char *path, const char *mode);
int fclose(FILE *stream);
size_t strlen(const char *s);
char *strchr(const char *s, int c);
char *strcat(char *dest, const char *src);
int socket(int domain, int type, int protocol);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, void *addrlen);
int connect(int sockfd, const struct sockaddr *addr, int addrlen);
long recv(int sockfd, void *buf, size_t len, int flags);

#define FILENAME_MAX 4096
#define BASEPATH "/tmp/"

static void stripNewlines(char *data) {
  char *replace = strchr(data, '\r');
  if (replace) *replace = '\0';
  replace = strchr(data, '\n');
  if (replace) *replace = '\0';
}

// CWE23_Relative_Path_Traversal__char_listen_socket_fopen_01
void bad_listen_socket(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  int listenSocket = socket(2, 1, 6);
  int acceptSocket;
  size_t dataLen = strlen(data);
  long recvResult;
  listen(listenSocket, 5);
  acceptSocket = accept(listenSocket, 0, 0);
  recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  stripNewlines(data);
  {
    FILE *pFile = fopen(data, "wb+"); // $ Alert
    if (pFile != 0) fclose(pFile);
  }
}

// CWE23_Relative_Path_Traversal__char_connect_socket_fopen_01
void bad_connect_socket(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  int connectSocket = socket(2, 1, 6);
  size_t dataLen = strlen(data);
  long recvResult;
  struct sockaddr service;
  connect(connectSocket, &service, sizeof(service));
  recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  stripNewlines(data);
  {
    FILE *pFile = fopen(data, "wb+"); // $ Alert
    if (pFile != 0) fclose(pFile);
  }
}

// CWE23_Relative_Path_Traversal__char_listen_socket_fopen_41 (data passed to a sink function).
// cpp/path-injection reports the outermost wrapper call of fopen, i.e. the call to badSink_41.
static void badSink_41(char *data) {
  FILE *pFile = fopen(data, "wb+");
  if (pFile != 0) fclose(pFile);
}

void bad_listen_socket_41(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  int acceptSocket = accept(socket(2, 1, 6), 0, 0);
  size_t dataLen = strlen(data);
  long recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  badSink_41(data); // $ Alert
}

// CWE23_Relative_Path_Traversal__char_listen_socket_fopen_42 (data returned from a source function)
static char *badSource_42(char *data) {
  int acceptSocket = accept(socket(2, 1, 6), 0, 0);
  size_t dataLen = strlen(data);
  long recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (FILENAME_MAX - dataLen - 1), 0); // $ Source
  if (recvResult == -1 || recvResult == 0) return data;
  data[dataLen + recvResult / sizeof(char)] = '\0';
  return data;
}

void bad_listen_socket_42(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  data = badSource_42(data);
  {
    FILE *pFile = fopen(data, "wb+"); // $ Alert
    if (pFile != 0) fclose(pFile);
  }
}

// goodG2B: a fixed file name is appended to the base path, so no alert is expected.
void good_fixed_file_name(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char *data = dataBuffer;
  strcat(data, "file.txt");
  {
    FILE *pFile = fopen(data, "wb+");
    if (pFile != 0) fclose(pFile);
  }
}

// Network data is received, but only a constant path is opened, so no alert is expected.
void good_unrelated_recv(void) {
  char dataBuffer[FILENAME_MAX] = BASEPATH;
  char recvBuffer[FILENAME_MAX];
  int acceptSocket = accept(socket(2, 1, 6), 0, 0);
  recv(acceptSocket, recvBuffer, sizeof(recvBuffer) - 1, 0);
  {
    FILE *pFile = fopen(dataBuffer, "wb+");
    if (pFile != 0) fclose(pFile);
  }
}
