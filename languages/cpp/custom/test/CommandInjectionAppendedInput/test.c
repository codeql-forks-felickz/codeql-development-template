typedef unsigned long size_t;
typedef long ssize_t;
typedef int wchar_t;
typedef struct FILE FILE;
extern FILE *stdin;

size_t strlen(const char *s);
size_t wcslen(const wchar_t *s);
int execlp(const char *file, const char *arg, ...);
char *strcat(char *dest, const char *src);
char *strchr(const char *s, int c);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t read(int fd, void *buf, size_t count);
char *fgets(char *s, int size, FILE *stream);
int system(const char *command);
FILE *popen(const char *command, const char *type);
int puts(const char *s);

#define FULL_COMMAND "ls "

// Juliet CWE78 `connect_socket_system` bad path: socket data is appended in place
// after a fixed command prefix and the whole buffer is executed.
void bad_juliet_connect_socket(int sock) {
  char *data;
  char data_buf[100] = FULL_COMMAND;
  data = data_buf;
  {
    int recvResult;
    char *replace;
    size_t dataLen = strlen(data);
    do {
      recvResult = recv(sock, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); // $ Source
      if (recvResult == -1 || recvResult == 0) {
        break;
      }
      data[dataLen + recvResult / sizeof(char)] = '\0';
      replace = strchr(data, '\n');
      if (replace) {
        *replace = '\0';
      }
    } while (0);
  }
  system(data); // $ Alert
}

void bad_inline_strlen(int sock) {
  char cmd[256] = "/usr/bin/ping -c 1 ";
  recv(sock, cmd + strlen(cmd), sizeof(cmd) - strlen(cmd) - 1, 0); // $ Source
  system(cmd); // $ Alert
}

void bad_array_index_read(int fd) {
  char cmd[256] = "cat ";
  size_t len = strlen(cmd);
  read(fd, &cmd[len], sizeof(cmd) - len - 1); // $ Source
  popen(cmd, "r"); // $ Alert
}

// Juliet `console_system` bad path: local (stdin) input appended in place.
void bad_fgets_appended(void) {
  char data_buf[100] = FULL_COMMAND;
  char *data = data_buf;
  size_t dataLen = strlen(data);
  fgets(data + dataLen, (int)(100 - dataLen), stdin); // $ Source
  system(data); // $ Alert
}

// Interprocedural flow, as in the Juliet 41/51/61 flow variants. `execute` is a
// command wrapper, so the alert is reported at the call to it.
static void execute(char *data) {
  system(data);
}

static char *source(int sock, char *data) {
  size_t dataLen = strlen(data);
  recv(sock, data + dataLen, 100 - dataLen - 1, 0); // $ Source
  return data;
}

void bad_interprocedural(int sock) {
  char data_buf[100] = FULL_COMMAND;
  execute(source(sock, data_buf)); // $ Alert
}

// Juliet `wchar_t_listen_socket_execlp` bad path: wide-string prefix measured with
// `wcslen`, filled by `recv` in a separate function, then run via `sh -c`.
static wchar_t *wide_source(int sock, wchar_t *data) {
  size_t dataLen = wcslen(data);
  recv(sock, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); // $ Source
  return data;
}

void bad_wide_execlp_sh_c(int sock) {
  wchar_t dataBuffer[100] = L"ls ";
  wchar_t *data = wide_source(sock, dataBuffer);
  execlp("sh", "sh", "-c", (char *)data, (char *)0); // $ Alert
}

// GOOD: Juliet goodG2B path, a fixed string is appended.
void good_fixed_suffix(void) {
  char data_buf[100] = FULL_COMMAND;
  char *data = data_buf;
  strcat(data, "*.*");
  system(data);
}

// GOOD (not in scope): the whole command comes from the peer, as in a remote
// shell. Like `cpp/command-line-injection`, this is not reported because no
// trusted prefix is extended.
void good_recv_whole_command(int sock) {
  char cmd[256];
  ssize_t n = recv(sock, cmd, sizeof(cmd) - 1, 0);
  if (n <= 0)
    return;
  cmd[n] = '\0';
  system(cmd);
}

// GOOD (not in scope): the offset is a running receive count, so the whole buffer
// is peer data rather than a trusted prefix followed by peer data.
void good_recv_loop_accumulate(int sock) {
  char cmd[256];
  size_t total = 0;
  ssize_t n;
  while ((n = recv(sock, cmd + total, sizeof(cmd) - total - 1, 0)) > 0)
    total += n;
  cmd[total] = '\0';
  system(cmd);
}

// GOOD: appended socket data never reaches a command execution sink.
void good_appended_not_executed(int sock) {
  char msg[256] = "received: ";
  recv(sock, msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, 0);
  puts(msg);
}

// GOOD: data is appended to a different buffer than the one that is executed.
void good_appended_other_buffer(int sock) {
  char log[256] = "peer: ";
  char cmd[256] = "ls ";
  recv(sock, log + strlen(log), sizeof(log) - strlen(log) - 1, 0);
  puts(log);
  system(cmd);
}
