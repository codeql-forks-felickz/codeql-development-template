typedef unsigned long size_t;
typedef unsigned long ULONG;
typedef int wchar_t;
typedef struct _FILE FILE;
typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;
typedef struct ldapcontrol LDAPControl;
struct l_timeval;

extern FILE *stdin;
char *fgets(char *s, int n, FILE *stream);
wchar_t *fgetws(wchar_t *s, int n, FILE *stream);
char *getenv(const char *name);
int recv(int s, char *buf, int len, int flags);
size_t strlen(const char *s);
int _snprintf(char *buffer, size_t count, const char *format, ...);
int _snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);

LDAP *ldap_initA(const char *host, ULONG port);
LDAP *ldap_initW(const wchar_t *host, ULONG port);
ULONG ldap_search_ext_sA(LDAP *ld, const char *base, ULONG scope, const char *filter,
                         char **attrs, ULONG attrsonly, LDAPControl **serverControls,
                         LDAPControl **clientControls, struct l_timeval *timeout,
                         ULONG sizeLimit, LDAPMessage **res);
ULONG ldap_search_ext_sW(LDAP *ld, const wchar_t *base, ULONG scope, const wchar_t *filter,
                         wchar_t **attrs, ULONG attrsonly, LDAPControl **serverControls,
                         LDAPControl **clientControls, struct l_timeval *timeout,
                         ULONG sizeLimit, LDAPMessage **res);
ULONG ldap_search_s(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs,
                    ULONG attrsonly, LDAPMessage **res);
ULONG ldap_searchA(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs,
                   ULONG attrsonly);

#define LDAP_SCOPE_SUBTREE 2
#define LDAP_PORT 389

/* Mirrors Juliet CWE90_LDAP_Injection__w32_char_console_01 (bad). */
void bad_char_console(void) {
  char dataBuffer[256] = "";
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  fgets(data + dataLen, (int)(256 - dataLen), stdin); // $ Source
  {
    LDAP *pLdapConnection = 0;
    LDAPMessage *pMessage = 0;
    char filter[256];
    _snprintf(filter, 256 - 1, "(cn=%s)", data);
    pLdapConnection = ldap_initA("localhost", LDAP_PORT);
    ldap_search_ext_sA(pLdapConnection, "base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, // $ Alert
                       &pMessage);
  }
}

/* Mirrors Juliet CWE90_LDAP_Injection__w32_wchar_t_console_01 (bad). */
void bad_wchar_console(void) {
  wchar_t dataBuffer[256] = L"";
  wchar_t *data = dataBuffer;
  fgetws(data, 256, stdin); // $ Source
  {
    LDAP *pLdapConnection = 0;
    LDAPMessage *pMessage = 0;
    wchar_t filter[256];
    _snwprintf(filter, 256 - 1, L"(cn=%s)", data);
    pLdapConnection = ldap_initW(L"localhost", LDAP_PORT);
    ldap_search_ext_sW(pLdapConnection, L"base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0, // $ Alert
                       &pMessage);
  }
}

/* Tainted base DN (DN injection) via environment variable. */
void bad_base_dn_env(LDAP *ld) {
  LDAPMessage *res = 0;
  char *base = getenv("LDAP_BASE"); // $ Source
  ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, "(objectClass=*)", 0, 0, &res); // $ Alert
}

/* Tainted filter from a network socket. */
void bad_filter_recv(LDAP *ld, int sock) {
  char buf[256];
  recv(sock, buf, 255, 0); // $ Source
  ldap_searchA(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, buf, 0, 0); // $ Alert
}

/* Mirrors Juliet goodG2B: hard-coded filter value, no alert expected. */
void good_constant_filter(void) {
  char *data = "Doe, Jane";
  LDAP *pLdapConnection = 0;
  LDAPMessage *pMessage = 0;
  char filter[256];
  _snprintf(filter, 256 - 1, "(cn=%s)", data);
  pLdapConnection = ldap_initA("localhost", LDAP_PORT);
  ldap_search_ext_sA(pLdapConnection, "base", LDAP_SCOPE_SUBTREE, filter, 0, 0, 0, 0, 0, 0,
                     &pMessage);
}

/* Tainted data is read but not used in the LDAP query, no alert expected. */
void good_unrelated_input(LDAP *ld) {
  LDAPMessage *res = 0;
  char buf[256];
  fgets(buf, 256, stdin);
  ldap_search_s(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, "(cn=fixed)", 0, 0, &res);
}
