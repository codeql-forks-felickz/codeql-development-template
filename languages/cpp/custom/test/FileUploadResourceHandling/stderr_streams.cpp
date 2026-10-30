// Minimal declarations so the test can be extracted without platform headers.
namespace std {
template <class CharT> class basic_ostream {
public:
  basic_ostream &operator<<(const CharT *s);
};
typedef basic_ostream<char> ostream;
extern ostream cout;
extern ostream cerr;
extern ostream clog;
} // namespace std

extern "C" void perror(const char *s);
const char *getPassword();

/* CWE-535: sensitive data written to standard error through C++ streams */

void cwe535_cerr_bad() {
  const char *password = getPassword();
  std::cerr << "Login failed with password: " << password; // $ Alert
}

void cwe535_clog_bad() {
  const char *userPassword = getPassword();
  std::clog << userPassword; // $ Alert
}

void cwe535_perror_bad() {
  const char *password = getPassword();
  perror(password); // $ Alert
}

void cwe535_cerr_good() {
  const char *password = getPassword();
  std::cerr << "Login failed";
  perror("login");
  /* Writing to standard output is not an error message (not CWE-535) */
  std::cout << password;
}
