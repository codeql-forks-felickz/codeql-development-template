---
category: newQuery
---
* Added a new query, `cpp/custom/command-line-injection-appended-input`, to detect user input that is read directly onto the end of an existing command string (for example `recv(sock, cmd + strlen(cmd), ...)`) and then executed with `system`, `popen` or a similar function. The standard `cpp/command-line-injection` query only reports flows through an explicit concatenation function such as `strcat` or `sprintf`, so it misses this in-place append pattern (for example the Juliet `CWE78_OS_Command_Injection` `connect_socket`/`listen_socket` test cases, including `wchar_t` buffers measured with `wcslen` and `sh -c` sinks such as `execlp`).
