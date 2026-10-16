#include "../decls.h"

/* What afl-clang-fast defines for __AFL_FUZZ_INIT / __AFL_FUZZ_TESTCASE_* */
extern unsigned char *__afl_fuzz_ptr;
extern unsigned int *__afl_fuzz_len;
#define __AFL_FUZZ_TESTCASE_BUF __afl_fuzz_ptr
#define __AFL_FUZZ_TESTCASE_LEN (*__afl_fuzz_len)

/* Damn_Vulnerable_C_Program libAFL/damn_vulnerable_c_program_shmem/imgRead.c */
int ProcessImage(char *filename) {
  unsigned char *shmem_buf = __AFL_FUZZ_TESTCASE_BUF;
  int bufsize = strlen((char *)shmem_buf); // BAD
  if (bufsize <= 12) {
    return 0;
  }
  printf("input: %s\n", shmem_buf); // BAD
  return 0;
}

int good_useLength() {
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  int len = __AFL_FUZZ_TESTCASE_LEN;
  char copy[64];
  if (len <= 0 || len >= 64)
    return 0;
  memcpy(copy, buf, len);
  copy[len] = '\0';
  printf("input: %s\n", copy);   // GOOD: null-terminated copy
  printf("input: %.*s\n", len, (char *)buf); // GOOD: explicit precision
  return (int)strlen(copy);      // GOOD
}
