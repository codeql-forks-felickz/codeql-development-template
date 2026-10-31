typedef unsigned long size_t;
typedef long ssize_t;
typedef struct _FILE FILE;
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t read(int fd, void *buf, size_t count);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct msghdr {
    void *msg_name;
    unsigned int msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

typedef struct _linkedList {
    struct _linkedList *next;
    struct _linkedList *prev;
} linkedList;

typedef struct _badStruct {
    linkedList list;
} badStruct;

typedef struct _plainStruct {
    int a;
    int b;
} plainStruct;

typedef struct _record {
    int id;
    char *name;
} record;

static linkedList *linkedListPrev, *linkedListNext;

/* Juliet CWE123_Write_What_Where_Condition__connect_socket_01 (bad) */
void bad_recv_over_list(int sock) {
    badStruct data;
    linkedList head = { &head, &head };
    data.list.next = head.next;
    data.list.prev = head.prev;
    head.next = &data.list;
    head.prev = &data.list;
    recv(sock, (char *)&data, sizeof(data), 0); // $ Source
    linkedListPrev = data.list.prev;
    linkedListNext = data.list.next;
    linkedListPrev->next = linkedListNext; // $ Alert
    linkedListNext->prev = linkedListPrev; // $ Alert
}

void bad_read_through_pointer(int fd, badStruct *p) {
    read(fd, p, sizeof(*p)); // $ Source
    p->list.next->prev = p->list.prev; // $ Alert
}

void bad_fread_record(FILE *f) {
    record r;
    fread(&r, sizeof(r), 1, f); // $ Source
    r.name[0] = 'x'; // $ Alert
}

void bad_recv_full_record(int sock) {
    record r;
    recv(sock, (char *)&r, sizeof(r), 0); // $ Source
    r.name[0] = 'x'; // $ Alert
}

void bad_recv_unknown_length(int sock, size_t length) {
    record r;
    recv(sock, (char *)&r, length, 0); // $ Source
    r.name[0] = 'x'; // $ Alert
}

void bad_recv_pointer_variable(int sock) {
    int *target;
    recv(sock, &target, sizeof(target), 0); // $ Source
    *target = 0; // $ Alert
}

static void unlinkSink(badStruct *data) {
    linkedList *prev = data->list.prev;
    linkedList *next = data->list.next;
    prev->next = next; // $ Alert
    next->prev = prev; // $ Alert
}

/* Juliet flow variant: the corrupted object is passed to another function. */
void bad_interprocedural(int sock) {
    badStruct data;
    linkedList head = { &head, &head };
    data.list.next = head.next;
    data.list.prev = head.prev;
    recv(sock, (char *)&data, sizeof(data), 0); // $ Source
    unlinkSink(&data);
}

/* Juliet CWE123_Write_What_Where_Condition__connect_socket_01 (goodG2B) */
void good_no_untrusted_input(void) {
    badStruct data;
    linkedList head = { &head, &head };
    data.list.next = head.next;
    data.list.prev = head.prev;
    head.next = &data.list;
    head.prev = &data.list;
    linkedListPrev = data.list.prev;
    linkedListNext = data.list.next;
    linkedListPrev->next = linkedListNext;
    linkedListNext->prev = linkedListPrev;
}

/* The object read from the socket contains no pointers. */
int good_plain_struct(int sock, int *table) {
    plainStruct s;
    recv(sock, (char *)&s, sizeof(s), 0);
    table[0] = s.a;
    return s.a + s.b;
}

/* Only a non-pointer field is read from untrusted data, and it is used as an index. */
void good_read_index_only(int sock, char *buffer) {
    record r;
    recv(sock, (char *)&r, sizeof(r), 0);
    if (r.id >= 0 && r.id < 16) {
        buffer[r.id] = 0;
    }
}

/* The pointers are reset to trusted values before they are dereferenced. */
void good_pointers_reset(int sock) {
    badStruct data;
    linkedList head = { &head, &head };
    recv(sock, (char *)&data, sizeof(data), 0);
    data.list.next = &head;
    data.list.prev = &head;
    linkedListPrev = data.list.prev;
    linkedListNext = data.list.next;
    linkedListPrev->next = linkedListNext;
    linkedListNext->prev = linkedListPrev;
}

/* Both branches replace the received pointer with trusted values. */
void good_conditional_pointer_resets(int sock, int condition) {
    badStruct data;
    linkedList head1 = { &head1, &head1 };
    linkedList head2 = { &head2, &head2 };
    recv(sock, (char *)&data, sizeof(data), 0);
    if (condition) {
        data.list.next = &head1;
    } else {
        data.list.next = &head2;
    }
    data.list.next->prev = &head1;
}

/* A branch that leaves the received pointer intact remains vulnerable. */
void bad_conditional_pointer_reset(int sock, int condition) {
    badStruct data;
    linkedList head = { &head, &head };
    recv(sock, (char *)&data, sizeof(data), 0); // $ Source
    if (condition) {
        data.list.next = &head;
    }
    data.list.next->prev = &head; // $ Alert
}

/* The input only reaches id, not the untouched name pointer. */
void good_recv_prefix_only(int sock) {
    record r = { 0, 0 };
    recv(sock, (char *)&r, sizeof(r.id), 0);
    r.name[0] = 'x';
}

/* getdelim returns a pointer to a buffer it allocated; the pointer is not attacker-chosen. */
void good_getdelim(FILE *f) {
    char *line = 0;
    size_t n = 0;
    ssize_t len = getdelim(&line, &n, '\n', f);
    if (len > 0) {
        line[len - 1] = '\0';
    }
}

/* recvmsg fills the buffers described by a program-owned msghdr; it does not overwrite its pointers. */
void good_recvmsg(int sock) {
    char buf[64];
    struct iovec iov = { buf, sizeof(buf) };
    struct msghdr msg = { 0, 0, &iov, 1, 0, 0, 0 };
    recvmsg(sock, &msg, 0);
    ((char *)msg.msg_iov[0].iov_base)[0] = 0;
    *(char *)msg.msg_iov->iov_base = 0;
}
