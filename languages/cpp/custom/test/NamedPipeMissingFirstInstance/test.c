typedef void *HANDLE;
typedef unsigned long DWORD;
typedef const char *LPCSTR;
typedef const unsigned short *LPCWSTR;
typedef void *LPSECURITY_ATTRIBUTES;

#define PIPE_ACCESS_INBOUND 0x00000001
#define PIPE_ACCESS_OUTBOUND 0x00000002
#define PIPE_ACCESS_DUPLEX 0x00000003
#define FILE_FLAG_FIRST_PIPE_INSTANCE 0x00080000
#define FILE_FLAG_OVERLAPPED 0x40000000
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define PIPE_TYPE_MESSAGE 0x00000004
#define PIPE_READMODE_MESSAGE 0x00000002
#define PIPE_WAIT 0x00000000
#define PIPE_UNLIMITED_INSTANCES 255
#define BUFSIZE 1024
#define NMPWAIT_USE_DEFAULT_WAIT 0x00000000

HANDLE CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances,
                        DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut,
                        LPSECURITY_ATTRIBUTES lpSecurityAttributes);
HANDLE CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances,
                        DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut,
                        LPSECURITY_ATTRIBUTES lpSecurityAttributes);

void bad1(void)
{
    HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\TestPipe", PIPE_ACCESS_DUPLEX, // $ Alert
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE,
                                    NMPWAIT_USE_DEFAULT_WAIT, 0);
}

void bad2(void)
{
    HANDLE hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\TestPipe", PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH, // $ Alert
                                    PIPE_TYPE_MESSAGE, 1, BUFSIZE, BUFSIZE, 0, 0);
}

void good1(void)
{
    HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\TestPipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE,
                                    NMPWAIT_USE_DEFAULT_WAIT, 0);
}

void good2(void)
{
    HANDLE hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\TestPipe",
                                    PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH,
                                    PIPE_TYPE_MESSAGE, 1, BUFSIZE, BUFSIZE, 0, 0);
}

void good3(DWORD openMode)
{
    // Non-constant open mode: cannot be determined statically, not reported.
    HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\TestPipe", openMode, PIPE_TYPE_MESSAGE, 1,
                                    BUFSIZE, BUFSIZE, 0, 0);
}
