// Minimal declarations; system headers cannot be used in qltest extraction.
typedef unsigned long size_t;
typedef int sig_atomic_t;
typedef void (*sighandler_t)(int);
typedef struct { unsigned long val[16]; } sigset_t;
typedef struct _FILE FILE;

struct siginfo;

struct sigaction {
  void (*sa_handler)(int);
  void (*sa_sigaction)(int, struct siginfo *, void *);
  sigset_t sa_mask;
  int sa_flags;
};

#define NULL ((void *)0)
#define SIGINT 2
#define SIGTERM 15
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_BLOCK 0
#define SIG_SETMASK 2

sighandler_t signal(int sig, sighandler_t handler);
int sigaction(int sig, const struct sigaction *act, struct sigaction *oact);
int sigprocmask(int how, const sigset_t *set, sigset_t *oset);
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
void *malloc(size_t size);
void free(void *ptr);
void exit(int status);
void _exit(int status);
int printf(const char *fmt, ...);
int fprintf(FILE *stream, const char *fmt, ...);
long write(int fd, const void *buf, size_t count);
extern FILE *stderr;

/* ===================== CWE-479: non-async-signal-safe calls ===================== */

// Juliet CWE479 basic_01: the handler calls malloc, free and exit.
static void helperBad479(int sig)
{
  void *voidPointer = malloc(10); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
  if (voidPointer == NULL) {
    exit(-1); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
  }
  free(voidPointer); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
}

static volatile sig_atomic_t volatileSigAtomic = 0;

// Safe: only sets a volatile sig_atomic_t flag.
static void helperGood479(int sig)
{
  volatileSigAtomic = sig;
}

void cwe479_bad(void)
{
  signal(SIGINT, helperBad479);
}

void cwe479_good(void)
{
  signal(SIGINT, helperGood479);
}

// The unsafe call is made in a helper that is only reached from the handler.
static void logMessage(const char *msg)
{
  fprintf(stderr, "%s\n", msg); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
}

static void indirectHandler(int sig)
{
  logMessage("caught signal");
}

// A handler registered through sigaction's sa_handler field.
static void sigactionHandler(int sig)
{
  printf("signal %d\n", sig); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
}

// A handler registered through sigaction's sa_sigaction field (designated initializer).
static void sigactionInfoHandler(int sig, struct siginfo *info, void *ctx)
{
  free(ctx); // $ Alert[cpp/custom/signal-handler-non-async-signal-safe-call]
}

// Safe: write and _exit are async-signal-safe.
static void safeExitHandler(int sig)
{
  write(2, "bye\n", 4);
  _exit(1);
}

void install_more(void)
{
  struct sigaction sa;
  struct sigaction sa2 = { .sa_sigaction = sigactionInfoHandler };
  signal(SIGTERM, indirectHandler);
  sa.sa_handler = sigactionHandler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa2, NULL);
  signal(SIGINT, safeExitHandler);
}

// Not a signal handler: unsafe calls here must not be reported.
void notAHandler(int x)
{
  void *p = malloc(x);
  printf("%p\n", p);
  free(p);
}

/* ===================== CWE-364: signal handler race condition ===================== */

typedef struct _structSigAtomic
{
  sig_atomic_t val;
} structSigAtomic;

structSigAtomic *gBad = NULL;
structSigAtomic *gGood = NULL;
structSigAtomic *gBlocked = NULL;
structSigAtomic *gSigaction = NULL;
structSigAtomic *gUnrelated = NULL;

static void helperBad364(int sig)
{
  if (gBad != NULL) {
    gBad->val = 2;
  }
}

static void helperGood364(int sig)
{
  if (gGood != NULL) {
    gGood->val = 2;
  }
}

static void helperBlocked364(int sig)
{
  if (gBlocked != NULL) {
    gBlocked->val = 2;
  }
}

static void touchSigaction(void)
{
  if (gSigaction != NULL) {
    gSigaction->val = 2;
  }
}

static void helperSigaction364(int sig)
{
  touchSigaction();
}

// Juliet CWE364 basic_01 bad(): the shared pointer is freed while the handler is installed.
void cwe364_bad(void)
{
  structSigAtomic *tmp = NULL;
  signal(SIGINT, SIG_DFL);
  if (gBad != NULL) {
    free(gBad); // safe: handler not installed yet
    gBad = NULL;
  }
  tmp = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  if (tmp == NULL) { exit(-1); }
  gBad = tmp;
  gBad->val = 1;
  signal(SIGINT, helperBad364);
  if (gBad != NULL) {
    free(gBad); // $ Alert[cpp/custom/signal-handler-race-condition]
    gBad = NULL;
  }
}

// Juliet CWE364 basic_01 good1(): the handler is disabled around the non-atomic update.
void cwe364_good(void)
{
  structSigAtomic *tmp = NULL;
  signal(SIGINT, SIG_DFL);
  if (gGood != NULL) {
    free(gGood);
    gGood = 0;
  }
  tmp = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  if (tmp == NULL) { exit(-1); }
  gGood = tmp;
  gGood->val = 1;
  signal(SIGINT, helperGood364);
  signal(SIGINT, SIG_DFL);
  if (gGood != NULL) {
    free(gGood);
    gGood = NULL;
  }
  signal(SIGINT, helperGood364);
}

// Safe: the signal is blocked with sigprocmask around the non-atomic update.
void cwe364_good_blocked(void)
{
  sigset_t set, old;
  gBlocked = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  signal(SIGINT, helperBlocked364);
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigprocmask(SIG_BLOCK, &set, &old);
  if (gBlocked != NULL) {
    free(gBlocked);
    gBlocked = NULL;
  }
  sigprocmask(SIG_SETMASK, &old, NULL);
}

// Bad: handler installed with sigaction; the global is accessed in a callee of the handler.
void cwe364_bad_sigaction(void)
{
  struct sigaction sa;
  gSigaction = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  sa.sa_handler = helperSigaction364;
  sigaction(SIGINT, &sa, NULL);
  if (gSigaction != NULL) {
    free(gSigaction); // $ Alert[cpp/custom/signal-handler-race-condition]
    gSigaction = NULL;
  }
}

// Safe: the freed global is not accessed by the installed handler.
void cwe364_good_unrelated(void)
{
  gUnrelated = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  signal(SIGINT, helperBad364);
  free(gUnrelated);
  gUnrelated = NULL;
}

// Bad: resetting the disposition of a different signal does not protect the update.
void cwe364_bad_other_signal_reset(void)
{
  gBad = (structSigAtomic *)malloc(sizeof(structSigAtomic));
  signal(SIGINT, helperBad364);
  signal(SIGTERM, SIG_DFL);
  free(gBad); // $ Alert[cpp/custom/signal-handler-race-condition]
  gBad = NULL;
}
