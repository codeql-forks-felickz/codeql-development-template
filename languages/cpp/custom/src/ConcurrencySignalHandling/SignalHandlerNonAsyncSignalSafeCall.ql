/**
 * @name Non-async-signal-safe function called from signal handler
 * @description Calling a function that is not async-signal-safe (such as `malloc`,
 *              `free`, `printf` or `exit`) from a signal handler can deadlock or
 *              corrupt program state if the signal interrupts the same function.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision high
 * @id cpp/custom/signal-handler-non-async-signal-safe-call
 * @tags security
 *       correctness
 *       concurrency
 *       external/cwe/cwe-479
 *       external/cwe/cwe-828
 */

import cpp
import SignalHandlers

/**
 * A well-known C library function that is not async-signal-safe according to
 * POSIX (it is absent from the list in `signal-safety(7)`), typically because it
 * uses locks, global state or the heap allocator.
 */
class NonAsyncSignalSafeFunction extends Function {
  NonAsyncSignalSafeFunction() {
    this.hasGlobalOrStdName([
        // heap allocation
        "malloc", "calloc", "realloc", "reallocarray", "free", "aligned_alloc", "posix_memalign",
        "memalign", "valloc", "strdup", "strndup",
        // stdio streams
        "printf", "fprintf", "vprintf", "vfprintf", "puts", "fputs", "putchar", "fputc", "putc",
        "fwrite", "fread", "fgets", "fgetc", "getc", "getchar", "scanf", "fscanf", "fopen",
        "fdopen", "freopen", "fclose", "fflush", "perror", "setvbuf",
        // process termination running atexit handlers / flushing streams
        "exit", "atexit", "quick_exit",
        // functions using static or locked global state
        "syslog", "vsyslog", "openlog", "closelog", "strtok", "strerror", "localtime", "gmtime",
        "ctime", "asctime", "mktime", "setlocale", "getpwnam", "getpwuid", "getgrnam", "getgrgid",
        "gethostbyname", "gethostbyaddr", "rand", "srand", "dlopen", "dlsym", "pthread_mutex_lock",
        "pthread_mutex_unlock"
      ])
  }
}

from SignalHandler handler, FunctionCall call, NonAsyncSignalSafeFunction target
where
  call.getTarget() = target and
  call.getEnclosingFunction() = handler.getAReachableFunction()
select call,
  "Call to non-async-signal-safe function '" + target.getName() +
    "' may be executed by signal handler $@.", handler, handler.getName()
