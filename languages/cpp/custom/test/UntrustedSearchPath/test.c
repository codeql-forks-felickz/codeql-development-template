typedef unsigned long size_t;
typedef int wchar_t;
typedef struct _IO_FILE FILE;
#define NULL ((void *)0)

int system(const char *command);
int _wsystem(const wchar_t *command);
FILE *popen(const char *command, const char *type);
FILE *_wpopen(const wchar_t *command, const wchar_t *mode);
int pclose(FILE *stream);
int execlp(const char *file, const char *arg, ...);
int execvp(const char *file, char *const argv[]);
char *strcpy(char *dest, const char *src);
wchar_t *wcscpy(wchar_t *dest, const wchar_t *src);
char *getenv(const char *name);

#define BAD_OS_COMMAND "ls -la"
#define GOOD_OS_COMMAND "/usr/bin/ls -la"
#define BAD_WIN_COMMAND L"cmd.exe /c dir"
#define GOOD_WIN_COMMAND L"c:\\windows\\system32\\cmd.exe /c dir"

/* Juliet CWE426_Untrusted_Search_Path__char_system_01 */
void char_system_bad()
{
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    strcpy(data, BAD_OS_COMMAND); // $ Source
    system(data); // $ Alert
}

void char_system_goodG2B()
{
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    strcpy(data, GOOD_OS_COMMAND);
    system(data);
}

/* Juliet CWE426_Untrusted_Search_Path__wchar_t_system_01 (Windows) */
void wchar_t_system_bad()
{
    wchar_t *data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    wcscpy(data, BAD_WIN_COMMAND); // $ Source
    _wsystem(data); // $ Alert
}

void wchar_t_system_goodG2B()
{
    wchar_t *data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    wcscpy(data, GOOD_WIN_COMMAND);
    _wsystem(data);
}

/* Juliet CWE426_Untrusted_Search_Path__char_popen_01 */
void char_popen_bad()
{
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    strcpy(data, BAD_OS_COMMAND); // $ Source
    {
        FILE *pipe = popen(data, "w"); // $ Alert
        if (pipe != NULL)
            pclose(pipe);
    }
}

void char_popen_goodG2B()
{
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    strcpy(data, GOOD_OS_COMMAND);
    {
        FILE *pipe = popen(data, "w");
        if (pipe != NULL)
            pclose(pipe);
    }
}

/* Juliet CWE426_Untrusted_Search_Path__wchar_t_popen_01 (Windows) */
void wchar_t_popen_bad()
{
    wchar_t *data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    wcscpy(data, BAD_WIN_COMMAND); // $ Source
    {
        FILE *pipe = _wpopen(data, L"wb"); // $ Alert
        if (pipe != NULL)
            pclose(pipe);
    }
}

void wchar_t_popen_goodG2B()
{
    wchar_t *data;
    wchar_t dataBuffer[100] = L"";
    data = dataBuffer;
    wcscpy(data, GOOD_WIN_COMMAND);
    {
        FILE *pipe = _wpopen(data, L"wb");
        if (pipe != NULL)
            pclose(pipe);
    }
}

/* Juliet flow variant 41/51: data passed to a sink function */
static void badSink(char *data)
{
    system(data); // $ Alert
}

void char_system_41_bad()
{
    char dataBuffer[100] = "";
    strcpy(dataBuffer, BAD_OS_COMMAND); // $ Source
    badSink(dataBuffer);
}

void char_system_41_goodG2B()
{
    char dataBuffer[100] = "";
    strcpy(dataBuffer, GOOD_OS_COMMAND);
    badSink(dataBuffer);
}

/* Juliet flow variant 67: data passed inside a struct */
typedef struct
{
    char *structFirst;
} structType;

static void structSink(structType myStruct)
{
    system(myStruct.structFirst); // $ Alert
}

void char_system_67_bad()
{
    char dataBuffer[100] = "";
    structType myStruct;
    strcpy(dataBuffer, BAD_OS_COMMAND); // $ Source
    myStruct.structFirst = dataBuffer;
    structSink(myStruct);
}

/* Direct literal arguments */
void direct_literals()
{
    system("whoami"); // $ Alert
    system("  ping -c 1 localhost"); // $ Alert
    execlp("ls", "ls", "-la", NULL); // $ Alert
    system("/bin/ls -la");
    system("C:\\Windows\\System32\\cmd.exe /c dir");
    system("./local-tool --flag");
    system("");
    execlp("/usr/bin/id", "id", NULL);
}

/* Non-constant commands are out of scope (covered by command-injection queries) */
void non_constant()
{
    system(getenv("CMD"));
}
