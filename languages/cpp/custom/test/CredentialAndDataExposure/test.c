// Minimal declarations so the test does not depend on system headers.
typedef unsigned long size_t;
typedef struct _FILE FILE;
typedef int wchar_t;
typedef void *HANDLE;
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef unsigned long HCRYPTKEY;
typedef unsigned long HCRYPTHASH;
typedef int errno_t;
typedef struct st_mysql MYSQL;

extern FILE *stdin;
FILE *fopen(const char *filename, const char *mode);
FILE *_wfopen(const wchar_t *filename, const wchar_t *mode);
errno_t fopen_s(FILE **pFile, const char *filename, const char *mode);
char *fgets(char *s, int n, FILE *stream);
wchar_t *fgetws(wchar_t *s, int n, FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
int fclose(FILE *stream);
int printf(const char *format, ...);

BOOL LogonUserA(const char *lpszUsername, const char *lpszDomain, const char *lpszPassword,
                DWORD dwLogonType, DWORD dwLogonProvider, HANDLE *phToken);
BOOL LogonUserW(const wchar_t *lpszUsername, const wchar_t *lpszDomain,
                const wchar_t *lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider,
                HANDLE *phToken);
BOOL CreateProcessWithLogonW(const wchar_t *lpUsername, const wchar_t *lpDomain,
                             const wchar_t *lpPassword, DWORD dwLogonFlags,
                             const wchar_t *lpApplicationName, wchar_t *lpCommandLine,
                             DWORD dwCreationFlags, void *lpEnvironment,
                             const wchar_t *lpCurrentDirectory, void *lpStartupInfo,
                             void *lpProcessInformation);
BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData,
                  DWORD *pdwDataLen);
MYSQL *mysql_real_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd,
                          const char *db, unsigned int port, const char *unix_socket,
                          unsigned long clientflag);
int CloseHandle(HANDLE h);

#define LOGON32_LOGON_NETWORK 3
#define LOGON32_PROVIDER_DEFAULT 0

/* Juliet CWE-256 pattern: plaintext password read from a file and used to log on. */
void bad_fgets_logon()
{
    char data[100] = "";
    HANDLE pHandle;
    FILE *pFile = fopen("passwords.txt", "r");
    if (pFile != 0)
    {
        if (fgets(data, 100, pFile) == 0) // $ Source
        {
            data[0] = '\0';
        }
        fclose(pFile);
    }
    if (LogonUserA("User", "Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle) != 0) // $ Alert
    {
        CloseHandle(pHandle);
    }
}

/* Wide-character variant. */
void bad_fgetws_logon()
{
    wchar_t data[100] = L"";
    HANDLE pHandle;
    FILE *pFile = _wfopen(L"passwords.txt", L"r");
    if (pFile != 0)
    {
        fgetws(data, 100, pFile); // $ Source
        fclose(pFile);
    }
    LogonUserW(L"User", L"Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle); // $ Alert
}

/* Password read in one function and used in another (Juliet flow variants). */
static void readPassword(char *data)
{
    FILE *pFile = fopen("passwords.txt", "r");
    if (pFile != 0)
    {
        fgets(data, 100, pFile); // $ Source
        fclose(pFile);
    }
}

static void usePassword(const char *password)
{
    HANDLE pHandle;
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle); // $ Alert
}

void bad_interprocedural()
{
    char data[100] = "";
    readPassword(data);
    usePassword(data);
}

/* fopen_s + fread into a buffer used for CreateProcessWithLogonW. */
void bad_fopen_s_fread()
{
    wchar_t data[100] = L"";
    FILE *pFile = 0;
    if (fopen_s(&pFile, "passwords.txt", "rb") == 0)
    {
        fread(data, sizeof(wchar_t), 99, pFile); // $ Source
        fclose(pFile);
    }
    CreateProcessWithLogonW(L"User", L"Domain", data, 0, L"app.exe", 0, 0, 0, 0, 0, 0); // $ Alert
}

/* Database password stored in plaintext in a configuration file. */
void bad_mysql(MYSQL *conn)
{
    char password[64] = "";
    FILE *cfg = fopen("db.conf", "r");
    if (cfg != 0)
    {
        fgets(password, sizeof(password), cfg); // $ Source
        fclose(cfg);
    }
    mysql_real_connect(conn, "localhost", "root", password, "app", 3306, 0, 0); // $ Alert
}

/* GOOD: the stored password is encrypted and decrypted before use (Juliet goodG2B). */
void good_decrypted(HCRYPTKEY hKey)
{
    char data[100] = "";
    HANDLE pHandle;
    DWORD dataLen;
    FILE *pFile = fopen("passwords.txt", "r");
    if (pFile != 0)
    {
        fgets(data, 100, pFile);
        fclose(pFile);
    }
    dataLen = 100;
    if (!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)data, &dataLen))
    {
        return;
    }
    LogonUserA("User", "Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle);
}

/* GOOD: password typed interactively, not stored on disk. */
void good_stdin()
{
    char data[100] = "";
    HANDLE pHandle;
    fgets(data, 100, stdin);
    LogonUserA("User", "Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle);
}

/* GOOD: data read from a file is not used as a credential. */
void good_not_credential()
{
    char data[100] = "";
    HANDLE pHandle;
    FILE *pFile = fopen("users.txt", "r");
    if (pFile != 0)
    {
        fgets(data, 100, pFile);
        fclose(pFile);
    }
    printf("%s\n", data);
    LogonUserA(data, "Domain", "unrelated", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle);
}
