typedef unsigned char SQLCHAR;
typedef short SQLSMALLINT;
int SQLConnect(void *connection, const SQLCHAR *serverName, SQLSMALLINT serverNameLength,
               const SQLCHAR *userName, SQLSMALLINT userNameLength,
               const SQLCHAR *authentication, SQLSMALLINT authenticationLength);

#define SQL_NTS -3

int main(int argc, char **argv) {
    SQLConnect(0, (const SQLCHAR *)argv[0], SQL_NTS, (const SQLCHAR *)"", SQL_NTS, // $ Alert
               (const SQLCHAR *)"", SQL_NTS);
    return argc;
}

void good_constant_connection_string(void) {
    SQLConnect(0, (const SQLCHAR *)"Example", SQL_NTS, (const SQLCHAR *)"", SQL_NTS,
               (const SQLCHAR *)"", SQL_NTS);
}