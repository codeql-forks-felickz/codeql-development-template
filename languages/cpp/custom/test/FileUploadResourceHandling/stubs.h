// Minimal declarations for the C runtime, BSD sockets and Win32 APIs used by
// the test cases, so that the tests can be extracted without platform headers.

typedef unsigned long size_t;
typedef struct _IO_FILE FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

char *fgets(char *s, int n, FILE *stream);
int fprintf(FILE *stream, const char *format, ...);
int fputs(const char *s, FILE *stream);
int printf(const char *format, ...);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcpy(char *dest, const char *src);

/* BSD sockets */
typedef unsigned int socklen_t;
struct in_addr {
  unsigned int s_addr;
};
struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};
struct sockaddr_in {
  short sin_family;
  unsigned short sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};
struct hostent {
  char *h_name;
  char **h_aliases;
  short h_addrtype;
  short h_length;
  char **h_addr_list;
};
#define AF_INET 2
int recv(int s, char *buf, int len, int flags);
int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int getpeername(int s, struct sockaddr *addr, socklen_t *addrlen);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags);
char *inet_ntoa(struct in_addr in);

/* Win32 */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef void *HMODULE;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef unsigned short WCHAR;
typedef const WCHAR *LPCWSTR;
typedef struct _STARTUPINFOA {
  DWORD cb;
} STARTUPINFOA;
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
} PROCESS_INFORMATION;
typedef enum _COMPUTER_NAME_FORMAT {
  ComputerNameNetBIOS,
  ComputerNamePhysicalDnsHostname
} COMPUTER_NAME_FORMAT;

HMODULE LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL FreeLibrary(HMODULE hLibModule);
BOOL SetComputerNameA(LPCSTR lpComputerName);
BOOL SetComputerNameW(LPCWSTR lpComputerName);
BOOL SetComputerNameExA(COMPUTER_NAME_FORMAT NameType, LPCSTR lpBuffer);
BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, void *lpProcessAttributes,
                    void *lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                    void *lpEnvironment, LPCSTR lpCurrentDirectory,
                    STARTUPINFOA *lpStartupInfo, PROCESS_INFORMATION *lpProcessInformation);
BOOL CloseHandle(HANDLE hObject);
#define NULL ((void *)0)
#define FALSE 0
