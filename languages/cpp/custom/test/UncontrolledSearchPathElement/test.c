typedef unsigned long size_t;
typedef long ssize_t;
typedef int wchar_t;
typedef struct _IO_FILE FILE;
#define NULL ((void *)0)

extern FILE *stdin;
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
int accept(int sockfd, void *addr, void *addrlen);
char *fgets(char *s, int size, FILE *stream);
char *getenv(const char *name);
size_t strlen(const char *s);
size_t wcslen(const wchar_t *s);
char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);
wchar_t *wcscat(wchar_t *dest, const wchar_t *src);
int putenv(char *string);
int _putenv(const char *envstring);
int _wputenv(const wchar_t *envstring);
int setenv(const char *name, const char *value, int overwrite);
int _putenv_s(const char *varname, const char *value_string);
int SetEnvironmentVariableA(const char *lpName, const char *lpValue);

/* Juliet CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01 */
void char_listen_socket_bad(int listenSocket)
{
    char *data;
    char dataBuffer[250] = "PATH=";
    data = dataBuffer;
    {
        size_t dataLen = strlen(data);
        int acceptSocket = accept(listenSocket, NULL, NULL);
        ssize_t recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); // $ Source
        if (recvResult <= 0)
            return;
        data[dataLen + recvResult / sizeof(char)] = '\0';
    }
    putenv(data); // $ Alert
}

void char_listen_socket_goodG2B()
{
    char *data;
    char dataBuffer[250] = "PATH=";
    data = dataBuffer;
    strcat(data, "/bin");
    putenv(data);
}

/* Juliet CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_01 (Windows) */
void wchar_t_listen_socket_bad(int listenSocket)
{
    wchar_t *data;
    wchar_t dataBuffer[250] = L"PATH=";
    data = dataBuffer;
    {
        size_t dataLen = wcslen(data);
        int acceptSocket = accept(listenSocket, NULL, NULL);
        ssize_t recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); // $ Source
        if (recvResult <= 0)
            return;
        data[dataLen + recvResult / sizeof(wchar_t)] = L'\0';
    }
    _wputenv(data); // $ Alert
}

void wchar_t_listen_socket_goodG2B()
{
    wchar_t *data;
    wchar_t dataBuffer[250] = L"PATH=";
    data = dataBuffer;
    wcscat(data, L"%SystemRoot%\\system32");
    _wputenv(data);
}

/* Juliet CWE427_Uncontrolled_Search_Path_Element__char_environment_01 */
void char_environment_bad()
{
    char *data;
    char dataBuffer[250] = "PATH=";
    data = dataBuffer;
    {
        size_t dataLen = strlen(data);
        char *environment = getenv("ADD"); // $ Source
        if (environment != NULL)
            strncat(data + dataLen, environment, 250 - dataLen - 1);
    }
    _putenv(data); // $ Alert
}

/* Juliet CWE427_Uncontrolled_Search_Path_Element__char_console_01 */
void char_console_bad()
{
    char *data;
    char dataBuffer[250] = "PATH=";
    data = dataBuffer;
    {
        size_t dataLen = strlen(data);
        if (250 - dataLen > 1)
            fgets(data + dataLen, (int)(250 - dataLen), stdin); // $ Source
    }
    putenv(data); // $ Alert
}

/* Name/value APIs */
void name_value_bad(int sock)
{
    char buf[256];
    recv(sock, buf, sizeof(buf) - 1, 0); // $ Source
    setenv("PATH", buf, 1); // $ Alert
    _putenv_s("LD_LIBRARY_PATH", buf); // $ Alert
    SetEnvironmentVariableA("Path", buf); // $ Alert
}

void name_value_not_search_path(int sock)
{
    char buf[256];
    recv(sock, buf, sizeof(buf) - 1, 0);
    setenv("LANG", buf, 1);
    SetEnvironmentVariableA("MY_SETTING", buf);
}

/* putenv with a non-search-path variable name */
void putenv_other_variable(int sock)
{
    char *data;
    char dataBuffer[250] = "LANG=";
    data = dataBuffer;
    recv(sock, data + 5, 200, 0);
    putenv(data);
}

/* Attacker controls the whole "NAME=value" string, so may set PATH */
void putenv_whole_string(int sock)
{
    char buf[256];
    recv(sock, buf, sizeof(buf) - 1, 0); // $ Source
    putenv(buf); // $ Alert
}
