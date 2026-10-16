# Uncontrolled data appended in place to an OS command

Code that builds an OS command by reading user input (for example from a socket, a file or the console) directly onto the end of a buffer that already contains a fixed command, and then runs that buffer with `system`, `popen` or a similar function, is vulnerable to command injection. An attacker can supply shell metacharacters such as `;`, `|` or `` ` `` to run arbitrary commands with the privileges of the program.

The standard `cpp/command-line-injection` query only reports user input that reaches a command through an explicit concatenation function (`strcat`, `sprintf` with `%s`, or `std::string` `operator+`). This query covers the equivalent *in-place* append, where input is written to `buf + strlen(buf)` or `&buf[strlen(buf)]` by a function such as `recv`, `read` or `fgets`. This has the same effect as `strcat(buf, input)`.

## Recommendation

Do not build shell commands from untrusted input. Prefer an API that runs a program with an explicit argument vector (for example `execve`) so that no shell interprets the input. If a shell command is unavoidable, strictly validate the input against an allow-list of expected values before using it.

## Example

The following code reads data from a TCP peer onto the end of the fixed command `ls ` and executes the result. A peer that sends `; rm -rf ~` causes a second command to run.

```c
char data[100] = "ls ";
size_t dataLen = strlen(data);
recv(sock, data + dataLen, sizeof(data) - dataLen - 1, 0);
system(data); // BAD
```

Validating the received data against an allow-list before it is used avoids the problem:

```c
char name[100];
ssize_t n = recv(sock, name, sizeof(name) - 1, 0);
if (n <= 0)
  return;
name[n] = '\0';
if (!is_known_directory(name)) // allow-list check
  return;
char *argv[] = {"ls", name, NULL};
execv("/bin/ls", argv); // GOOD: no shell is involved
```

## Limitations

- Input that is passed to a command wrapper only through a function pointer is not reported, because the shared `shellCommand` library predicate only recognizes direct calls to wrapper functions.
- Flow through pointer-to-pointer, C++ reference or class-member aliasing of the command buffer may not be tracked.

## References

- OWASP: [Command Injection](https://owasp.org/www-community/attacks/Command_Injection).
- Common Weakness Enumeration: [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Common Weakness Enumeration: [CWE-88](https://cwe.mitre.org/data/definitions/88.html).
