typedef unsigned long size_t;
typedef void *HANDLE;
typedef int BOOL;
typedef unsigned long DWORD;

BOOL LogonUserA(const char *username, const char *domain, const char *password,
                DWORD logonType, DWORD provider, HANDLE *token);
void *malloc(size_t size);
void free(void *ptr);
void *SecureZeroMemory(void *ptr, size_t size);
char *fgets(char *buffer, int count, void *stream);

void bad_stack_password(void *stream)
{
    char data[64];
    fgets(data, 64, stream);
    LogonUserA("user", "domain", data, 3, 0, 0); // $ Alert
}

void good_stack_password(void *stream)
{
    char data[64];
    fgets(data, 64, stream);
    LogonUserA("user", "domain", data, 3, 0, 0);
    SecureZeroMemory(data, sizeof(data));
}

void bad_heap_password(void *stream)
{
    char *data = (char *)malloc(64);
    fgets(data, 64, stream);
    LogonUserA("user", "domain", data, 3, 0, 0);
    free(data); // $ Alert
}

void good_heap_password(void *stream)
{
    char *data = (char *)malloc(64);
    fgets(data, 64, stream);
    LogonUserA("user", "domain", data, 3, 0, 0);
    SecureZeroMemory(data, 64);
    free(data);
}
