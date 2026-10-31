typedef int BOOL;
typedef void *HANDLE;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef enum { SecurityAnonymous, SecurityIdentification, SecurityImpersonation } SECURITY_IMPERSONATION_LEVEL;

BOOL ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL level);
BOOL ImpersonateLoggedOnUser(HANDLE token);
BOOL ImpersonateNamedPipeClient(HANDLE pipe);
BOOL RevertToSelf(void);
BOOL SetThreadToken(HANDLE *thread, HANDLE token);
int setuid(uid_t uid);
int setgid(gid_t gid);
int seteuid(uid_t uid);
int setresuid(uid_t r, uid_t e, uid_t s);
int printf(const char *fmt, ...);
void exit(int status);

// Juliet-style: the result of ImpersonateSelf is ignored, so on failure the
// thread keeps running with the process token.
void impersonate_bad() {
  ImpersonateSelf(SecurityImpersonation); // $ Alert
  printf("doing work\n");
  RevertToSelf(); // $ Alert
}

void impersonate_user_bad(HANDLE token, HANDLE pipe) {
  ImpersonateLoggedOnUser(token); // $ Alert
  ImpersonateNamedPipeClient(pipe); // $ Alert
  SetThreadToken(0, token); // $ Alert
}

void drop_privileges_bad(uid_t uid, gid_t gid) {
  setgid(gid); // $ Alert
  setuid(uid); // $ Alert
  seteuid(uid); // $ Alert
  setresuid(uid, uid, uid); // $ Alert
}

// --- Safe counterparts: no alerts expected below ---

void impersonate_good() {
  if (!ImpersonateSelf(SecurityImpersonation)) {
    exit(1);
  }
  printf("doing work\n");
  if (!RevertToSelf()) {
    exit(1);
  }
}

void drop_privileges_good(uid_t uid, gid_t gid) {
  if (setgid(gid) != 0)
    exit(1);
  if (setuid(uid) != 0)
    exit(1);
  int r = seteuid(uid);
  if (r == -1)
    exit(1);
}

BOOL impersonate_return_good(HANDLE token) {
  return ImpersonateLoggedOnUser(token);
}

// Explicitly discarding the result is still unsafe for privilege changes.
void explicit_discard_bad(uid_t uid) {
  (void)setuid(uid); // $ Alert
}
