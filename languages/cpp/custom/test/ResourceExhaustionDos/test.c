typedef unsigned long size_t;
typedef long ssize_t;
typedef struct _IO_FILE FILE;
typedef union { char __size[40]; long __align; } pthread_mutex_t;

extern FILE *stdin;
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *fp);
size_t fread(void *ptr, size_t size, size_t n, FILE *fp);
char *fgets(char *s, int n, FILE *fp);
int sscanf(const char *s, const char *fmt, ...);
int atoi(const char *s);
size_t strlen(const char *s);
unsigned long strtoul(const char *s, char **end, int base);
int fscanf(FILE *fp, const char *fmt, ...);
unsigned int sleep(unsigned int seconds);
void printLine(const char *s);
void *malloc(size_t size);
void free(void *ptr);
void exit(int status);
ssize_t recv(int fd, void *buf, size_t len, int flags);
int pthread_mutex_init(pthread_mutex_t *m, const void *attr);
int pthread_mutex_lock(pthread_mutex_t *m);
int pthread_mutex_unlock(pthread_mutex_t *m);
int pthread_mutex_destroy(pthread_mutex_t *m);
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function);

#define assert(expr) ((expr) ? (void)0 : __assert_fail(#expr, __FILE__, __LINE__, __func__))

#define MAX_LOOP 10000
#define ASSERT_VALUE 5
#define MAX_RECURSION 10
#define UINT_MAX 4294967295U

void sink(int x);

/* ---------- CWE-606: unchecked input for loop condition ---------- */

void loop_bound_console_bad(void)
{
    char data[100] = "";
    int i, n, count = 0;
    if (fgets(data, 100, stdin) != 0 && sscanf(data, "%d", &n) == 1)
    {
        for (i = 0; i < n; i++) // $ Alert
        {
            count++;
        }
        sink(count);
    }
}

void loop_bound_socket_bad(int sock)
{
    char buf[32];
    int i, n, count = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    n = atoi(buf);
    i = 0;
    while (i < n) // $ Alert
    {
        count++;
        i++;
    }
    sink(count);
}

void loop_bound_socket_reversed_bad(int sock)
{
    char buf[32];
    int i, n, count = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    n = atoi(buf);
    for (i = 0; n > i; i++) // $ Alert
    {
        count++;
    }
    sink(count);
}

void loop_bound_checked_good(void)
{
    char data[100] = "";
    int i, n, count = 0;
    if (fgets(data, 100, stdin) != 0 && sscanf(data, "%d", &n) == 1)
    {
        if (n < MAX_LOOP)
        {
            for (i = 0; i < n; i++)
            {
                count++;
            }
        }
        sink(count);
    }
}

void loop_bound_early_exit_good(int sock)
{
    char buf[32];
    int i, n, count = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    n = atoi(buf);
    if (n > MAX_LOOP)
        return;
    for (i = 0; i < n; i++)
    {
        count++;
    }
    sink(count);
}

void loop_bound_expression_bad(int sock)
{
    char nBuf[32];
    char limitBuf[32];
    int i, n, limit, count = 0;
    if (fgets(nBuf, sizeof(nBuf), stdin) == 0 ||
        fgets(limitBuf, sizeof(limitBuf), stdin) == 0)
        return;
    n = atoi(nBuf);
    limit = atoi(limitBuf);
    if (n < limit)
    {
        for (i = 0; i < n; i++) // $ Alert
        {
            count++;
        }
    }
    sink(count);
}

void loop_bound_expression_checked_good(int sock)
{
    char buf[32];
    int i, n, limit = 100, count = 0;
    if (fgets(buf, sizeof(buf), stdin) == 0)
        return;
    n = atoi(buf);
    if (n < limit)
    {
        for (i = 0; i < n; i++)
        {
            count++;
        }
    }
    sink(count);
}

void loop_bound_capped_good(int sock)
{
    char buf[32];
    int i, n, count = 0;
    if (fgets(buf, sizeof(buf), stdin) == 0)
        return;
    n = atoi(buf);
    for (i = 0; i < n && i < 100; i++)
    {
        count++;
    }
    sink(count);
}

void loop_bound_constant_good(void)
{
    char data[100] = "15";
    int i, n, count = 0;
    if (sscanf(data, "%d", &n) == 1)
    {
        for (i = 0; i < n; i++)
        {
            count++;
        }
        sink(count);
    }
}

void loop_over_input_length_good(int sock)
{
    char buf[32];
    size_t i;
    int count = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    for (i = 0; i < strlen(buf); i++)
    {
        count += buf[i];
    }
    sink(count);
}

/* CWE-400: the bound is cast before the comparison. */
void loop_bound_cast_bad(int sock)
{
    char buf[32];
    int count = -1;
    size_t i;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        count = atoi(buf);
    }
    for (i = 0; i < (size_t)count; i++) // $ Alert
    {
        printLine("Hello");
    }
}

void loop_bound_cast_good(int sock)
{
    char buf[32];
    int count = -1;
    size_t i;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        count = atoi(buf);
    }
    if (count >= 0 && count <= 20)
    {
        for (i = 0; i < (size_t)count; i++)
        {
            printLine("Hello");
        }
    }
}

/* ---------- CWE-400: untrusted sleep duration ---------- */

void sleep_duration_bad(void)
{
    char inLine[64];
    int i;
    if (fgets(inLine, 64, stdin) == 0)
        return;
    i = atoi(inLine);
    sleep(i); // $ Alert
}

void sleep_duration_upper_bound_only_bad(void)
{
    char inLine[64];
    int i;
    if (fgets(inLine, 64, stdin) == 0)
        return;
    i = atoi(inLine);
    if (i > 10)
        return;
    sleep(i); // $ Alert
}

void sleep_duration_nonnegative_good(void)
{
    char inLine[64];
    int i;
    if (fgets(inLine, sizeof(inLine), stdin) == 0)
        return;
    i = atoi(inLine);
    if (i < 0 || i > 10)
        return;
    sleep(i);
}

void sleep_reassigned_after_check_bad(void)
{
    char first[64];
    char second[64];
    int i;
    if (fgets(first, sizeof(first), stdin) == 0 ||
        fgets(second, sizeof(second), stdin) == 0)
        return;
    i = atoi(first);
    if (i < 100)
    {
        i = atoi(second);
        sleep(i); // $ Alert
    }
}

/* ---------- CWE-789: uncontrolled allocation size ---------- */

void alloc_size_socket_bad(int sock)
{
    char buf[32];
    size_t data = 0;
    char *myString;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = strtoul(buf, 0, 0);
    }
    if (data > strlen("hello"))
    {
        myString = (char *)malloc(data * sizeof(char)); // $ Alert
        if (myString == 0)
            exit(-1);
        free(myString);
    }
}

void alloc_size_fscanf_bad(void)
{
    size_t data = 0;
    char *myString;
    fscanf(stdin, "%zu", &data);
    if (data > strlen("hello"))
    {
        myString = (char *)malloc(data * sizeof(char)); // $ Alert
        if (myString == 0)
            exit(-1);
        free(myString);
    }
}

void alloc_size_checked_good(int sock)
{
    char buf[32];
    size_t data = 0;
    char *myString;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = strtoul(buf, 0, 0);
    }
    if (data > strlen("hello") && data < 100)
    {
        myString = (char *)malloc(data * sizeof(char));
        if (myString == 0)
            exit(-1);
        free(myString);
    }
}

void alloc_size_signed_upper_bound_only_bad(int sock)
{
    char buf[32];
    int data = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = atoi(buf);
    }
    if (data > 100)
        return;
    free(malloc(data)); // $ Alert
}

void alloc_size_signed_nonnegative_good(int sock)
{
    char buf[32];
    int data = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = atoi(buf);
    }
    if (data < 0 || data > 100)
        return;
    free(malloc(data));
}

/* No comparison at all: reported by cpp/uncontrolled-allocation-size, not by this query. */
void alloc_size_unchecked_other_query(int sock)
{
    char buf[32];
    size_t data = 0;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = strtoul(buf, 0, 0);
    }
    free(malloc(data));
}

void alloc_size_constant_good(void)
{
    size_t data = 20;
    char *myString = (char *)malloc(data * sizeof(char));
    free(myString);
}

/* ---------- CWE-617: reachable assertion ---------- */

void reachable_assertion_bad(int sock)
{
    char buf[32];
    int data = -1;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = atoi(buf);
    }
    assert(data > ASSERT_VALUE); // $ Alert
}

void reachable_assertion_guarded_bad(int sock)
{
    char buf[32];
    int data = -1;
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r > 0)
    {
        buf[r] = '\0';
        data = atoi(buf);
    }
    if (data > 10)
        return;
    assert(data > ASSERT_VALUE); // $ Alert
}

void reachable_assertion_good(void)
{
    int data = ASSERT_VALUE + 1;
    assert(data > ASSERT_VALUE);
}

/* ---------- CWE-674: uncontrolled recursion ---------- */

void stack_operation(void)
{
    char buff[0x1000];
    while (1)
    {
        stack_operation(); // $ Alert
    }
}

static void infinite_helper_bad(void)
{
    infinite_helper_bad(); // $ Alert
}

static void unbounded_helper_bad(unsigned level)
{
    if (level == 0)
    {
        return;
    }
    unbounded_helper_bad(level - 1);
}

void unbounded_recursion_bad(void)
{
    unbounded_helper_bad(UINT_MAX); // $ Alert
}

void tainted_recursion_bad(int sock)
{
    char buf[32];
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    unbounded_helper_bad(atoi(buf)); // $ Alert
}

static void unbounded_helper_base_case_bad(unsigned level)
{
    if (level > 0)
    {
        unbounded_helper_base_case_bad(level - 1);
    }
}

void tainted_base_case_recursion_bad(int sock)
{
    char buf[32];
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    if (r <= 0)
        return;
    buf[r] = '\0';
    unbounded_helper_base_case_bad(atoi(buf)); // $ Alert
}

void huge_base_case_recursion_bad(void)
{
    unbounded_helper_base_case_bad(UINT_MAX); // $ Alert
}

static void bounded_helper_good(unsigned level)
{
    if (level > MAX_RECURSION)
    {
        return;
    }
    if (level == 0)
    {
        return;
    }
    bounded_helper_good(level - 1);
}

void bounded_recursion_good(int sock)
{
    char buf[32];
    ssize_t r = recv(sock, buf, sizeof(buf) - 1, 0);
    bounded_helper_good(UINT_MAX);
    if (r <= 0)
        return;
    buf[r] = '\0';
    bounded_helper_good(atoi(buf));
}

void small_recursion_good(void)
{
    unbounded_helper_bad(5);
}

static void halving_helper_good(unsigned level)
{
    if (level == 0)
        return;
    halving_helper_good(level / 2);
}

void halving_recursion_good(void)
{
    halving_helper_good(UINT_MAX);
}

/* Unbounded allocation loop: reported by cpp/memory-never-freed, not by this query. */
void heap_exhaustion_bad(int size)
{
    char *buff;
    do
    {
        buff = (char *)malloc(size);
    } while (buff);
}

void heap_retry_good(int size)
{
    char *buff;
    do
    {
        buff = (char *)malloc(size);
        if (buff)
            free(buff);
    } while (buff);
}

/* ---------- CWE-667: lock not released ---------- */

void lock_not_released_bad(void)
{
    static pthread_mutex_t badLock;
    pthread_mutex_init(&badLock, 0);
    pthread_mutex_lock(&badLock); // $ Alert
}

void lock_released_good(void)
{
    static pthread_mutex_t goodLock;
    pthread_mutex_init(&goodLock, 0);
    pthread_mutex_lock(&goodLock);
    pthread_mutex_unlock(&goodLock);
    pthread_mutex_destroy(&goodLock);
}

pthread_mutex_t globalLock;

void lock_global_wrapper_good(void)
{
    pthread_mutex_lock(&globalLock);
}

void lock_param_wrapper_good(pthread_mutex_t *m)
{
    pthread_mutex_lock(m);
}

void lock_param_alias_wrapper_good(pthread_mutex_t *m)
{
    pthread_mutex_t *local = m;
    pthread_mutex_lock(local);
}

void lock_local_pointer_release_good(void)
{
    static pthread_mutex_t localLock;
    pthread_mutex_t *local = &localLock;
    pthread_mutex_lock(local);
    pthread_mutex_unlock(&localLock);
}

/* ---------- CWE-401 / CWE-775: covered by existing queries ----------
 * cpp/memory-may-not-be-freed, cpp/memory-never-freed, cpp/file-may-not-be-closed
 * and cpp/file-never-closed report these, so this query must not.
 */

struct Image
{
    char header[4];
    int width;
    int height;
    char data[10];
};

void overwritten_pointer_leak(FILE *fp)
{
    struct Image img;
    while (fread(&img, sizeof(img), 1, fp) > 0)
    {
        int size3 = img.width / img.height;
        char *buff4 = (char *)malloc(size3);
        if (size3 > 10)
        {
            buff4 = 0;
        }
        else
        {
            free(buff4);
        }
    }
}

void malloc_never_freed(void)
{
    char *data = (char *)malloc(100);
    if (data == 0)
        exit(-1);
    data[0] = 'A';
    sink(data[0]);
}

int early_return_file_leak(const char *filename)
{
    struct Image img;
    FILE *fp = fopen(filename, "r");
    if (fp == 0)
        exit(0);
    while (fread(&img, sizeof(img), 1, fp) > 0)
    {
        if (img.height == 0)
            return 0;
    }
    fclose(fp);
    return 0;
}

void file_never_closed(void)
{
    FILE *data = fopen("BadSource_fopen.txt", "w+");
}
