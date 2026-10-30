typedef struct _FILE FILE;
#define NULL ((void *)0)
#define F_OK 0
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

int access(const char *pathname, int mode);
FILE *fopen(const char *pathname, const char *mode);
int fputs(const char *s, FILE *stream);
int fclose(FILE *stream);
int printf(const char *format, ...);
int remove(const char *pathname);
int chmod(const char *pathname, int mode);
int open(const char *pathname, int flags, ...);

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
const char *global_tmp_path = "/tmp/global.tmp";

void check_then_open_global(void)
{
    if (access(global_tmp_path, F_OK) != 0) {
        FILE *f = fopen(global_tmp_path, "w"); // $ Alert
        if (f != NULL) {
            fclose(f);
        }
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
