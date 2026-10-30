typedef unsigned long size_t;
typedef long ssize_t;
#define SIZE_MAX (~(size_t)0)
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
int atoi(const char *nptr);
unsigned long strtoul(const char *nptr, char **endptr, int base);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void exit(int status);
void printIntLine(int);

static int readCount(int sock) {
    char inputBuffer[32];
    int recvResult = recv(sock, inputBuffer, 31, 0); // $ Source
    if (recvResult == -1 || recvResult == 0) {
        return -1;
    }
    inputBuffer[recvResult] = '\0';
    return atoi(inputBuffer);
}

/* Juliet CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_connect_socket_01 (bad) */
void bad_juliet(int sock) {
    int data;
    data = -1;
    {
        char inputBuffer[32];
        int recvResult = recv(sock, inputBuffer, 31, 0); // $ Source
        if (recvResult == -1 || recvResult == 0) {
            return;
        }
        inputBuffer[recvResult] = '\0';
        data = atoi(inputBuffer);
    }
    {
        size_t i;
        int *intPointer;
        intPointer = (int*)malloc(data * sizeof(int)); // $ Alert
        if (intPointer == 0) {exit(-1);}
        /* The loop bound comparison happens after the allocation and does not limit `data`. */
        for (i = 0; i < (size_t)data; i++)
        {
            intPointer[i] = 0;
        }
        printIntLine(intPointer[0]);
        free(intPointer);
    }
}

void bad_interprocedural(int sock) {
    int count = readCount(sock);
    long *values = (long *)malloc(count * sizeof(long)); // $ Alert
    free(values);
}

void bad_constant_multiplier(int sock) {
    int count = readCount(sock);
    char *records = (char *)malloc(count * 16); // $ Alert
    free(records);
}

void bad_realloc(int sock, int *old) {
    int count = readCount(sock);
    int *grown = (int *)realloc(old, sizeof(int) * count); // $ Alert
    free(grown);
}

/* Lower bound only: a large unsigned count still wraps. */
void bad_lower_bound_only(int sock) {
    char inputBuffer[32];
    recv(sock, inputBuffer, 31, 0); // $ Source
    inputBuffer[31] = '\0';
    size_t count = strtoul(inputBuffer, 0, 10);
    if (count > 0) {
        int *p = (int *)malloc(count * sizeof(int)); // $ Alert
        free(p);
    }
}

/* Juliet CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_connect_socket_01 (goodG2B) */
void good_constant_count(void) {
    int data;
    size_t i;
    int *intPointer;
    data = -1;
    data = 20;
    intPointer = (int*)malloc(data * sizeof(int));
    if (intPointer == 0) {exit(-1);}
    for (i = 0; i < (size_t)data; i++) {
        intPointer[i] = 0;
    }
    free(intPointer);
}

/* The count is bounded before it is multiplied. */
void good_bounded(int sock) {
    int count = readCount(sock);
    if (count > 0 && count < 1000) {
        int *p = (int *)malloc(count * sizeof(int));
        free(p);
    }
}

/* The multiplication is checked against SIZE_MAX before allocating. */
void good_overflow_check(int sock) {
    int count = readCount(sock);
    if (count <= 0 || (size_t)count > SIZE_MAX / sizeof(int)) {
        return;
    }
    int *p = (int *)malloc(count * sizeof(int));
    free(p);
}

/* calloc performs its own overflow check on nmemb * size. */
void good_calloc(int sock) {
    int count = readCount(sock);
    int *p = (int *)calloc(count, sizeof(int));
    free(p);
}

/* No multiplication: the allocation size cannot wrap. */
void good_no_multiplication(int sock) {
    int count = readCount(sock);
    char *p = (char *)malloc(count);
    free(p);
}
