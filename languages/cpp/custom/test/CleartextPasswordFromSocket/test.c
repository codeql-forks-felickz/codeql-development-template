typedef unsigned long size_t;
typedef void *HANDLE;
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned long HCRYPTKEY;
typedef unsigned long HCRYPTHASH;
typedef unsigned char BYTE;

int recv(int socket, void *buffer, size_t length, int flags);
int recvfrom(int socket, void *buffer, size_t length, int flags, void *address,
             unsigned long *addressLength);
BOOL LogonUserA(const char *username, const char *domain, const char *password,
                DWORD logonType, DWORD provider, HANDLE *token);
BOOL CryptDecrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags,
                  BYTE *data, DWORD *dataLength);

void bad_socket_password(int socket)
{
    char password[64];
    recv(socket, password, sizeof(password), 0); // $ Source
    LogonUserA("user", "domain", password, 3, 0, 0); // $ Alert
}

void good_socket_username(int socket)
{
    char username[64];
    char password[] = "local";
    recvfrom(socket, username, sizeof(username), 0, 0, 0);
    LogonUserA(username, "domain", password, 3, 0, 0);
}

void good_encrypted_socket_password(int socket)
{
    char password[64];
    DWORD dataLength = sizeof(password);
    recv(socket, password, sizeof(password), 0);
    CryptDecrypt(0, 0, 1, 0, (BYTE *)password, &dataLength);
    LogonUserA("user", "domain", password, 3, 0, 0);
}
