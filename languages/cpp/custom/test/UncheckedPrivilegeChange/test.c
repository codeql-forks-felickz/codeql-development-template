typedef int BOOL;
typedef void *HANDLE;
typedef unsigned int uid_t;

BOOL ImpersonateNamedPipeClient(HANDLE hNamedPipe);
BOOL ImpersonateLoggedOnUser(HANDLE hToken);
BOOL RevertToSelf(void);
BOOL SetThreadToken(HANDLE *Thread, HANDLE Token);
int setuid(uid_t uid);
void exit(int status);
void doPrivilegedWork(void);

void bad1(HANDLE hPipe)
{
    ImpersonateNamedPipeClient(hPipe); // $ Alert
    doPrivilegedWork();
    RevertToSelf(); // $ Alert
}

void bad2(HANDLE hToken)
{
    (void)ImpersonateLoggedOnUser(hToken); // $ Alert
    doPrivilegedWork();
}

void bad3(HANDLE hToken)
{
    SetThreadToken(0, hToken); // $ Alert
    setuid(1000); // $ Alert
}

void good1(HANDLE hPipe)
{
    if (!ImpersonateNamedPipeClient(hPipe))
    {
        exit(1);
    }
    doPrivilegedWork();
    if (!RevertToSelf())
    {
        exit(1);
    }
}

void good2(HANDLE hToken)
{
    BOOL ok = ImpersonateLoggedOnUser(hToken);
    if (!ok)
    {
        exit(1);
    }
    if (setuid(1000) != 0)
    {
        exit(1);
    }
}

int good3(HANDLE hToken)
{
    return SetThreadToken(0, hToken);
}
