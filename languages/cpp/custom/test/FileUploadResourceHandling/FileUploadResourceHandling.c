#include "stubs.h"

void printLine(const char *line);

/* ---------------------------------------------------------------------------
 * CWE-15: External control of a system or configuration setting
 * (Juliet CWE15_External_Control_of_System_or_Configuration_Setting__w32_01)
 * ------------------------------------------------------------------------- */

void cwe15_bad(int acceptSocket) {
  char data[100] = "";
  int recvResult = recv(acceptSocket, data, 99, 0);
  if (recvResult <= 0) {
    return;
  }
  data[recvResult] = '\0';
  if (!SetComputerNameA(data)) { // $ Alert
    printLine("Failure setting computer name");
  }
}

void cwe15_bad_console(void) {
  char data[100] = "";
  if (fgets(data, 100, stdin) == NULL) {
    return;
  }
  if (!SetComputerNameExA(ComputerNamePhysicalDnsHostname, data)) { // $ Alert
    printLine("Failure setting computer name");
  }
}

void cwe15_good(void) {
  char data[100] = "";
  strcpy(data, "hostname");
  if (!SetComputerNameA(data)) {
    printLine("Failure setting computer name");
  }
}

/* ---------------------------------------------------------------------------
 * CWE-247: Reliance on DNS lookups in a security decision
 * (Juliet CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01)
 * ------------------------------------------------------------------------- */

void cwe247_bad(int listenSocket) {
  struct sockaddr_in service;
  socklen_t serviceLen = sizeof(service);
  struct hostent *hostEntry;
  int acceptSocket = accept(listenSocket, (struct sockaddr *)&service, &serviceLen);
  if (acceptSocket < 0) {
    return;
  }
  hostEntry = gethostbyaddr((char *)&service.sin_addr, sizeof(service.sin_addr), AF_INET);
  if (hostEntry != NULL && strcmp(hostEntry->h_name, "trustme.example.com") == 0) { // $ Alert
    printLine("Access granted.");
  } else {
    printLine("Access denied.");
  }
}

void cwe247_bad_getnameinfo(int acceptSocket) {
  struct sockaddr_in peer;
  socklen_t peerLen = sizeof(peer);
  char host[256];
  int trusted;
  if (getpeername(acceptSocket, (struct sockaddr *)&peer, &peerLen) != 0) {
    return;
  }
  if (getnameinfo((struct sockaddr *)&peer, peerLen, host, sizeof(host), NULL, 0, 0) != 0) {
    return;
  }
  trusted = strncmp(host, "trustme.example.com", 19); // $ Alert
  if (trusted == 0) {
    printLine("Access granted.");
  }
}

void cwe247_good(int listenSocket) {
  struct sockaddr_in service;
  socklen_t serviceLen = sizeof(service);
  int acceptSocket = accept(listenSocket, (struct sockaddr *)&service, &serviceLen);
  if (acceptSocket < 0) {
    return;
  }
  /* Decision based on the peer IP address rather than a reverse DNS lookup */
  if (strcmp(inet_ntoa(service.sin_addr), "192.168.30.123") == 0) {
    printLine("Access granted.");
  }
}

void cwe247_good_logging_only(int listenSocket) {
  struct sockaddr_in service;
  socklen_t serviceLen = sizeof(service);
  struct hostent *hostEntry;
  int acceptSocket = accept(listenSocket, (struct sockaddr *)&service, &serviceLen);
  if (acceptSocket < 0) {
    return;
  }
  hostEntry = gethostbyaddr((char *)&service.sin_addr, sizeof(service.sin_addr), AF_INET);
  if (hostEntry != NULL) {
    /* The host name is only logged, not used to make a decision */
    printLine(hostEntry->h_name);
  }
}

/* ---------------------------------------------------------------------------
 * CWE-535: Exposure of information through shell error message
 * (Juliet CWE535_Info_Exposure_Shell_Error__w32_char_01)
 * ------------------------------------------------------------------------- */

void cwe535_bad(void) {
  char password[100] = "";
  size_t passwordLen = 0;
  if (fgets(password, 100, stdin) == NULL) {
    password[0] = '\0';
  }
  passwordLen = strlen(password);
  if (passwordLen > 0) {
    password[passwordLen - 1] = '\0';
  }
  fprintf(stderr, "User attempted access with password: %s\n", password); // $ Alert
  fputs(password, stderr); // $ Alert
}

void cwe535_good(void) {
  char password[100] = "";
  if (fgets(password, 100, stdin) == NULL) {
    password[0] = '\0';
  }
  fprintf(stderr, "User attempted access\n");
  /* Writing a non-sensitive value to stderr is fine */
  fprintf(stderr, "Login attempt for user: %s\n", "User");
}

/* ---------------------------------------------------------------------------
 * CWE-114: Process control (untrusted library load)
 * (Juliet CWE114_Process_Control__w32_char_console_01 / _listen_socket_01)
 * LoadLibrary/LoadLibraryA/LoadLibraryW are already covered by the standard
 * `cpp/uncontrolled-process-operation` query, so this query only reports the
 * LoadLibraryEx variants that the standard query does not model.
 * ------------------------------------------------------------------------- */

void cwe114_console_bad(void) {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  size_t dataLen = strlen(data);
  HMODULE hModule;
  if (100 - dataLen > 1) {
    if (fgets(data + dataLen, (int)(100 - dataLen), stdin) != NULL) {
      dataLen = strlen(data);
      if (dataLen > 0 && data[dataLen - 1] == '\n') {
        data[dataLen - 1] = '\0';
      }
    }
  }
  /* Reported by cpp/uncontrolled-process-operation, not by this query */
  hModule = LoadLibraryA(data);
  if (hModule != NULL) {
    FreeLibrary(hModule);
  }
}

void cwe114_listen_socket_ex_bad(int acceptSocket) {
  char data[100] = "";
  HMODULE hModule;
  int recvResult = recv(acceptSocket, data, 99, 0);
  if (recvResult <= 0) {
    return;
  }
  data[recvResult] = '\0';
  hModule = LoadLibraryExA(data, NULL, 0); // $ Alert
  if (hModule != NULL) {
    FreeLibrary(hModule);
  }
}

void cwe114_good(void) {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  HMODULE hModule;
  strcpy(data, "C:\\Windows\\System32\\winsrv.dll");
  hModule = LoadLibraryExA(data, NULL, 0);
  if (hModule != NULL) {
    FreeLibrary(hModule);
  }
}

/* ---------------------------------------------------------------------------
 * CWE-428: Unquoted search path or element
 * (Juliet CWE428_Unquoted_Search_Path_or_Element__w32_01)
 * The standard `cpp/unsafe-create-process-call` query reports string literals
 * and `char *` variables, but misses a writable `char[]` command line buffer
 * initialized from a literal (as CreateProcessW requires).
 * ------------------------------------------------------------------------- */

void cwe428_bad(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char commandLine[100] = "C:\\Program Files\\GoodApp arg1 arg2";
  if (!CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { // $ Alert
    printLine("CreateProcess failed");
    return;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
}

void cwe428_bad_unsized(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char commandLine[] = "C:\\Program Files\\GoodApp arg1 arg2";
  CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); // $ Alert
}

void cwe428_pointer_covered_by_standard_query(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char *commandLine = "C:\\Program Files\\GoodApp arg1 arg2";
  /* Reported by cpp/unsafe-create-process-call, not by this query */
  CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void cwe428_good_quoted(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char commandLine[100] = "\"C:\\Program Files\\GoodApp\" arg1 arg2";
  CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void cwe428_good_no_spaces(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char commandLine[100] = "C:\\Tools\\GoodApp.exe";
  CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void cwe428_good_app_name(void) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  char commandLine[100] = "C:\\Program Files\\GoodApp arg1 arg2";
  CreateProcessA("C:\\Program Files\\GoodApp.exe", commandLine, NULL, NULL, FALSE, 0, NULL, NULL,
                 &si, &pi);
}
