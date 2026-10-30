typedef unsigned long size_t;
typedef long ssize_t;
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

struct Base {
    Base *next;
};

struct Derived : Base {};

struct PlainBase {
    int value;
};

struct PlainDerived : PlainBase {};

void bad_inherited_pointer_field(int sock) {
    Derived data;
    recv(sock, (char *)&data, sizeof(data), 0); // $ Source
    data.next->next = &data; // $ Alert
}

void good_inherited_plain_field(int sock) {
    PlainDerived data;
    recv(sock, (char *)&data, sizeof(data), 0);
    data.value = 42;
}
