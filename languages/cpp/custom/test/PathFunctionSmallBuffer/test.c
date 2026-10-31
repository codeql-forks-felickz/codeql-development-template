typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned short wchar_t;
#define MAX_PATH 260
#define PATH_MAX 4096
#define BAD_PATH_SIZE (MAX_PATH / 2)

DWORD GetCurrentDirectoryA(DWORD, char *);
BOOL PathAppendA(char *, const char *);
BOOL PathAppendW(wchar_t *, const wchar_t *);
char *PathCombineA(char *, const char *, const char *);
char *realpath(const char *, char *);
void exit(int);

/* Juliet CWE785_Path_Manipulation_Function_Without_Max_Sized_Buffer__w32_01 */
void cwe785_bad() {
  char path[BAD_PATH_SIZE];
  DWORD length;
  length = GetCurrentDirectoryA(BAD_PATH_SIZE, path);
  if (length == 0 || length >= BAD_PATH_SIZE)
    exit(1);
  if (!PathAppendA(path, "AAAAAAAAAAAA")) // $ Alert
    exit(1);
}

void wide_bad() {
  wchar_t path[100];
  PathAppendW(path, L"x"); // $ Alert
}

void combine_bad(const char *a, const char *b) {
  char out[64];
  PathCombineA(out, a, b); // $ Alert
}

void realpath_bad(const char *p) {
  char resolved[256];
  realpath(p, resolved); // $ Alert
}

/* Safe: the buffer has MAX_PATH elements. */
void cwe785_good() {
  char path[MAX_PATH];
  DWORD length;
  length = GetCurrentDirectoryA(MAX_PATH, path);
  if (length == 0 || length >= MAX_PATH)
    exit(1);
  if (!PathAppendA(path, "AAAAAAAAAAAA"))
    exit(1);
}

/* Safe: `realpath` allocates the result when passed a null buffer. */
void realpath_good(const char *p) {
  char resolved[PATH_MAX];
  realpath(p, resolved);
  realpath(p, 0);
}
