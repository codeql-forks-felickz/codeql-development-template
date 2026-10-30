// Minimal stand-ins for <winsock2.h>, <winldap.h>, <ldap.h>, <stdio.h> and <stdlib.h>.
typedef unsigned long size_t;
typedef unsigned long ULONG;
typedef int wchar_t;
typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;
typedef struct ldapcontrol LDAPControl;
typedef struct timeval_s { long tv_sec; long tv_usec; } timeval_t;
typedef struct berval_s { unsigned long bv_len; char *bv_val; } berval;
typedef struct FILE FILE;
extern FILE *stdin;

#define LDAP_PORT 389
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_NO_LIMIT 0

int recv(int s, char *buf, int len, int flags);
char *getenv(const char *name);
char *fgets(char *s, int n, FILE *stream);
int atoi(const char *s);
int snprintf(char *s, size_t n, const char *format, ...);
int _snprintf(char *s, size_t n, const char *format, ...);
int _snwprintf(wchar_t *s, size_t n, const wchar_t *format, ...);
char *strcat(char *dest, const char *src);
char *strcpy(char *dest, const char *src);
size_t strlen(const char *s);

/* WinLDAP */
LDAP *ldap_initA(const char *host, ULONG port);
ULONG ldap_bind_sA(LDAP *ld, const char *dn, const char *cred, ULONG method);
ULONG ldap_search_ext_sA(LDAP *ld, const char *base, ULONG scope, const char *filter,
                         char **attrs, ULONG attrsonly, LDAPControl **server, LDAPControl **client,
                         struct timeval_s *timeout, ULONG sizelimit, LDAPMessage **res);
ULONG ldap_search_ext_sW(LDAP *ld, const wchar_t *base, ULONG scope, const wchar_t *filter,
                         wchar_t **attrs, ULONG attrsonly, LDAPControl **server, LDAPControl **client,
                         struct timeval_s *timeout, ULONG sizelimit, LDAPMessage **res);
ULONG ldap_search_sA(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs,
                     ULONG attrsonly, LDAPMessage **res);
ULONG ldap_unbind(LDAP *ld);

/* OpenLDAP */
int ldap_search_ext_s(LDAP *ld, const char *base, int scope, const char *filter, char **attrs,
                      int attrsonly, LDAPControl **sctrls, LDAPControl **cctrls,
                      struct timeval_s *timeout, int sizelimit, LDAPMessage **res);
int ldap_search_ext(LDAP *ld, const char *base, int scope, const char *filter, char **attrs,
                    int attrsonly, LDAPControl **sctrls, LDAPControl **cctrls,
                    struct timeval_s *timeout, int sizelimit, int *msgidp);
int ldap_bv2escaped_filter_value(berval *in, berval *out);

/* Juliet CWE90_LDAP_Injection__w32_char_connect_socket_01 style: socket data into the filter. */
void bad_socket_winldap(int connectSocket)
{
    char dataBuffer[256] = "";
    char *data = dataBuffer;
    size_t dataLen = strlen(data);
    int recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (256 - dataLen - 1), 0); // $ Source
    if (recvResult <= 0) return;
    data[dataLen + recvResult / sizeof(char)] = '\0';
    {
        LDAP *pLdapConnection = 0;
        LDAPMessage *pMessage = 0;
        char filter[256];
        /* POTENTIAL FLAW: data concatenated into LDAP search, which could result in LDAP Injection */
        _snprintf(filter, 256 - 1, "(cn=%s)", data);
        pLdapConnection = ldap_initA("localhost", LDAP_PORT);
        if (pLdapConnection == 0) return;
        if (ldap_bind_sA(pLdapConnection, 0, 0, 0) != 0) return;
        ldap_search_ext_sA(pLdapConnection, "base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, // $ Alert
                           LDAP_NO_LIMIT, LDAP_NO_LIMIT, &pMessage);
        ldap_unbind(pLdapConnection);
    }
}

/* Juliet CWE90_LDAP_Injection__w32_wchar_t_connect_socket_01 style: wide-char variant. */
void bad_socket_winldap_wide(int connectSocket)
{
    wchar_t dataBuffer[256] = L"";
    wchar_t *data = dataBuffer;
    wchar_t filter[256];
    LDAPMessage *pMessage = 0;
    LDAP *ld = 0;
    int recvResult = recv(connectSocket, (char *)data, sizeof(wchar_t) * (256 - 1), 0); // $ Source
    if (recvResult <= 0) return;
    data[recvResult / sizeof(wchar_t)] = L'\0';
    _snwprintf(filter, 256 - 1, L"(cn=%s)", data);
    ldap_search_ext_sW(ld, L"base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &pMessage); // $ Alert
}

/* Environment variable flows straight into a WinLDAP synchronous search. */
void bad_env_search_s(LDAP *ld)
{
    LDAPMessage *res;
    char filter[256] = "(uid=";
    char *user = getenv("LDAP_USER"); // $ Source
    if (!user) return;
    strcat(filter, user);
    strcat(filter, ")");
    ldap_search_sA(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, &res); // $ Alert
}

/* OpenLDAP API with stdin input. */
void bad_stdin_openldap(LDAP *ld)
{
    LDAPMessage *res;
    char input[100];
    char filter[256];
    int msgid;
    if (fgets(input, sizeof(input), stdin) == 0) return; // $ Source
    snprintf(filter, sizeof(filter), "(&(objectClass=person)(cn=%s))", input);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res); // $ Alert
    ldap_search_ext(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &msgid); // $ Alert
}

/* Tainted value passed through a helper that performs the search. */
static void run_search(LDAP *ld, const char *filter)
{
    LDAPMessage *res;
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res); // $ Alert
}

void bad_interprocedural(LDAP *ld, int sock)
{
    char buf[128];
    char filter[256];
    int n = recv(sock, buf, sizeof(buf) - 1, 0); // $ Source
    if (n <= 0) return;
    buf[n] = 0;
    snprintf(filter, sizeof(filter), "(mail=%s)", buf);
    run_search(ld, filter);
}

/* ---------------- Safe counterparts: no alerts expected ---------------- */

/* GOOD: Juliet goodG2B, the filter is built from a constant. */
void good_constant(LDAP *ld)
{
    LDAPMessage *pMessage = 0;
    char data[100] = "Doe, Jane";
    char filter[256];
    _snprintf(filter, 256 - 1, "(cn=%s)", data);
    ldap_search_ext_sA(ld, "base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &pMessage);
}

/* GOOD: the tainted value is converted to an integer before use. */
void good_integer(LDAP *ld, int sock)
{
    LDAPMessage *res;
    char buf[32];
    char filter[256];
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    int id;
    if (n <= 0) return;
    buf[n] = 0;
    id = atoi(buf);
    snprintf(filter, sizeof(filter), "(uidNumber=%d)", id);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res);
}

/* GOOD: user-defined escaping of LDAP filter metacharacters (RFC 4515). */
static void escape_ldap_filter(const char *in, char *out, size_t outLen)
{
    static const char hex[] = "0123456789abcdef";
    size_t j = 0;
    for (; *in && j + 3 < outLen; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '*' || c == '(' || c == ')' || c == '\\' || c == 0) {
            out[j++] = '\\';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 0xf];
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = 0;
}

void good_escaped(LDAP *ld, int sock)
{
    LDAPMessage *res;
    char buf[128];
    char safe[512];
    char filter[600];
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = 0;
    escape_ldap_filter(buf, safe, sizeof(safe));
    snprintf(filter, sizeof(filter), "(cn=%s)", safe);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res);
}

/* GOOD: user-defined validation that rejects LDAP metacharacters before copying. */
char *strpbrk(const char *s, const char *accept);
static int sanitize_ldap_value(const char *in, char *out, size_t outLen)
{
    if (strpbrk(in, "*()\\") != 0) return -1;
    snprintf(out, outLen, "%s", in);
    return 0;
}

void good_sanitized(LDAP *ld, int sock)
{
    LDAPMessage *res;
    char buf[128];
    char safe[128];
    char filter[256];
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = 0;
    if (sanitize_ldap_value(buf, safe, sizeof(safe)) != 0) return;
    snprintf(filter, sizeof(filter), "(cn=%s)", safe);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res);
}

/* GOOD: OpenLDAP's ldap_bv2escaped_filter_value escapes the value. */
void good_openldap_escaped(LDAP *ld, int sock)
{
    LDAPMessage *res;
    char buf[128];
    char filter[600];
    berval in, out;
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = 0;
    in.bv_val = buf;
    in.bv_len = n;
    if (ldap_bv2escaped_filter_value(&in, &out) != 0) return;
    snprintf(filter, sizeof(filter), "(cn=%s)", out.bv_val);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, &res);
}

/* GOOD: tainted data only reaches the bind password, not a search filter. */
void good_not_filter(LDAP *ld, int sock)
{
    LDAPMessage *res;
    char pw[64];
    int n = recv(sock, pw, sizeof(pw) - 1, 0);
    if (n <= 0) return;
    pw[n] = 0;
    ldap_bind_sA(ld, "cn=admin", pw, 0);
    ldap_search_ext_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, "(objectClass=*)", 0, 0, 0, 0, 0, 0, &res);
}
