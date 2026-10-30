typedef struct _FILE FILE;
#define NULL ((void *)0)
#define F_OK 0
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define O_CREAT 1
#define O_EXCL 2

typedef int wchar_t;

struct stat_buffer {
    int st_mode;
};

int access(const char *pathname, int mode);
FILE *fopen(const char *pathname, const char *mode);
int _wfopen_s(FILE **file, const wchar_t *filename, const wchar_t *mode);
int fputs(const char *s, FILE *stream);
int fclose(FILE *stream);
int printf(const char *format, ...);
int remove(const char *pathname);
int chmod(const char *pathname, int mode);
int open(const char *pathname, int flags, ...);
int stat(const char *pathname, struct stat_buffer *buf);

#define MY_TMP_FILE "/tmp/file.tmp"
#define OTHER_TMP_FILE "/tmp/other.tmp"

// Reduced from the AI Scan finding: access() then fopen() on a predictable,
// macro-defined /tmp path.
int symlink_attack_macro(void)
{
    FILE *tmpFile;
    if (!access(MY_TMP_FILE, F_OK)) {
        printf("File exists!\n");
        return EXIT_FAILURE;
    }
    tmpFile = fopen(MY_TMP_FILE, "w"); // $ Alert
    if (tmpFile == NULL) {
        return EXIT_FAILURE;
    }
    fputs("Some text...\n", tmpFile);
    fclose(tmpFile);
    return EXIT_SUCCESS;
}

// Same pattern with string literals written out at both call sites.
int symlink_attack_literal(void)
{
    if (access("/tmp/literal.tmp", F_OK) == 0) {
        return EXIT_FAILURE;
    }
    FILE *f = fopen("/tmp/literal.tmp", "w"); // $ Alert
    if (f == NULL) {
        return EXIT_FAILURE;
    }
    fclose(f);
    return EXIT_SUCCESS;
}

void check_then_wfopen_s(void)
{
    FILE *f;
    if (access("/tmp/wide.tmp", F_OK) != 0) {
        _wfopen_s(&f, L"/tmp/wide.tmp", L"w"); // $ Alert
    }
}

// Check guards the use directly (positive branch).
void check_then_remove_constant(void)
{
    if (access(MY_TMP_FILE, F_OK) == 0) {
        remove(MY_TMP_FILE); // $ Alert
    }
}

// Check then sensitive operation on a constant path.
void check_then_chmod_constant(void)
{
    if (!access(MY_TMP_FILE, F_OK)) {
        chmod(MY_TMP_FILE, 0644); // $ Alert
    }
}

// Path held in a global variable.
const char * const global_tmp_path = "/tmp/global.tmp";

void check_then_open_global(void)
{
    if (access(global_tmp_path, F_OK) != 0) {
        FILE *f = fopen(global_tmp_path, "w"); // $ Alert
        if (f != NULL) {
            fclose(f);
        }
    }
}

const char *reassignable_global_path = "/tmp/reassigned-a.tmp";

void check_then_open_reassigned_global(void)
{
    if (access(reassignable_global_path, F_OK) != 0) {
        reassignable_global_path = "/tmp/reassigned-b.tmp";
        fopen(reassignable_global_path, "w");
    }
}

void exclusive_open_after_check(void)
{
    if (access("/tmp/exclusive-open.tmp", F_OK) == 0) {
        return;
    }
    open("/tmp/exclusive-open.tmp", O_CREAT | O_EXCL, 0600);
}

void exclusive_fopen_after_check(void)
{
    if (access("/tmp/exclusive-fopen.tmp", F_OK) == 0) {
        return;
    }
    fopen("/tmp/exclusive-fopen.tmp", "wx");
}

void exclusive_open_then_chmod(void)
{
    if (open("/tmp/exclusive-chmod.tmp", O_CREAT | O_EXCL, 0600) < 0) {
        return;
    }
    chmod("/tmp/exclusive-chmod.tmp", 0644); // $ Alert
}

void stat_then_guard_then_use(void)
{
    struct stat_buffer s;
    stat("/tmp/stat-before.tmp", &s);
    if (s.st_mode != 0) {
        chmod("/tmp/stat-before.tmp", 0644); // $ Alert
    }
}

void guard_before_stat_does_not_check(void)
{
    struct stat_buffer s;
    if (s.st_mode != 0) {
        chmod("/tmp/stat-after.tmp", 0644);
    }
    stat("/tmp/stat-after.tmp", &s);
}

void stat_result_overwritten_before_guard(void)
{
    struct stat_buffer s;
    stat("/tmp/stat-overwritten.tmp", &s);
    s.st_mode = 1;
    if (s.st_mode != 0) {
        chmod("/tmp/stat-overwritten.tmp", 0644);
    }
}

// Negative for this query: a path held in a stack variable is already
// reported by the standard cpp/toctou-race-condition query, so it is not
// reported again here.
void check_then_open_variable(const char *path)
{
    if (access(path, F_OK) != 0) {
        FILE *f = fopen(path, "w");
        if (f != NULL) {
            fclose(f);
        }
    }
}

// Negative: check and use are on different constant paths.
int different_constant_paths(void)
{
    if (!access(MY_TMP_FILE, F_OK)) {
        return EXIT_FAILURE;
    }
    FILE *f = fopen(OTHER_TMP_FILE, "w");
    if (f == NULL) {
        return EXIT_FAILURE;
    }
    fclose(f);
    return EXIT_SUCCESS;
}

// Negative: the access() result does not guard the fopen().
void unguarded_constant_path(void)
{
    access(MY_TMP_FILE, F_OK);
    FILE *f = fopen(MY_TMP_FILE, "w");
    if (f != NULL) {
        fclose(f);
    }
}

// Negative: open the file directly, without a separate check.
int open_without_check(void)
{
    FILE *f = fopen(MY_TMP_FILE, "w");
    if (f == NULL) {
        return EXIT_FAILURE;
    }
    fclose(f);
    return EXIT_SUCCESS;
}

// Negative: the same constant path is checked in one function and used in
// another, so there is no guard relationship.
int only_check(void)
{
    return access(MY_TMP_FILE, F_OK);
}

void only_use(void)
{
    FILE *f = fopen(MY_TMP_FILE, "w");
    if (f != NULL) {
        fclose(f);
    }
}
