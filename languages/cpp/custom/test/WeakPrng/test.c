#include "../WinCryptStubs/wincrypt.h"

int rand(void);
long random(void);
void srand(unsigned int seed);
void printIntLine(int value);

void rand_bad(void) {
  int data = rand(); // $ Alert
  printIntLine(data);
}

long random_bad(void) {
  return random(); // $ Alert
}

void discarded_rand_good(void) {
  srand(42);
  rand();
}

void crypt_gen_random_good(HCRYPTPROV hProv) {
  unsigned int data;
  CryptGenRandom(hProv, sizeof(data), (BYTE *)&data);
  printIntLine(data);
}
