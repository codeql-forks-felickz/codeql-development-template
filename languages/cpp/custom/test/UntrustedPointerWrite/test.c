typedef unsigned long size_t;
typedef long ssize_t;
typedef struct FILE FILE;
extern FILE *stdin;
char *fgets(char *, int, FILE *);
ssize_t recv(int, void *, size_t, int);
void exit(int);

typedef struct _linkedList {
  struct _linkedList *next;
  struct _linkedList *prev;
} linkedList;

typedef struct _badStruct {
  linkedList list;
} badStruct;

static linkedList *linkedListPrev, *linkedListNext;

/* Juliet CWE123_Write_What_Where_Condition__fgets_01 */
void cwe123_fgets_bad() {
  badStruct data;
  linkedList head = {&head, &head};
  data.list.next = head.next;
  data.list.prev = head.prev;
  head.next = &data.list;
  head.prev = &data.list;
  if (fgets((char *)&data, sizeof(data), stdin) == 0) // $ Source
    exit(1);
  linkedListPrev = data.list.prev;
  linkedListNext = data.list.next;
  linkedListPrev->next = linkedListNext; // $ Alert
  linkedListNext->prev = linkedListPrev; // $ Alert
}

/* Juliet CWE123_Write_What_Where_Condition__listen_socket_01 */
void cwe123_socket_bad(int s) {
  badStruct data;
  linkedList head = {&head, &head};
  data.list.next = head.next;
  data.list.prev = head.prev;
  head.next = &data.list;
  head.prev = &data.list;
  if (recv(s, (char *)&data, sizeof(data), 0) <= 0) // $ Source
    exit(1);
  data.list.prev->next = data.list.next; // $ Alert
  data.list.next->prev = data.list.prev; // $ Alert
}

/* Untrusted pointer written through with the dereference operator. */
void deref_bad(int s) {
  int *p;
  if (recv(s, (char *)&p, sizeof(p), 0) <= 0) // $ Source
    exit(1);
  *p = 0; // $ Alert
}

/* Safe: the list pointers are not overwritten with untrusted data. */
void cwe123_good() {
  badStruct data;
  linkedList head = {&head, &head};
  data.list.next = head.next;
  data.list.prev = head.prev;
  head.next = &data.list;
  head.prev = &data.list;
  linkedListPrev = data.list.prev;
  linkedListNext = data.list.next;
  linkedListPrev->next = linkedListNext;
  linkedListNext->prev = linkedListPrev;
}

/* Safe: untrusted data is read into a buffer, and the pointer is not tainted. */
void buffer_good(int s) {
  char buf[16];
  char *p = buf;
  if (recv(s, buf, sizeof(buf), 0) <= 0)
    exit(1);
  p[0] = buf[1];
  *p = 'a';
}
