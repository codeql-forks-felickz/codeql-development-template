# Write through a pointer read from untrusted data

Reading untrusted bytes (for example from a network socket or a file) directly over an object that stores pointers gives an attacker control over those pointers. If the program later writes through one of them, the attacker chooses the address of the write, and often the value written as well. This is a *write-what-where* condition (CWE-123), which usually leads to arbitrary code execution.

A typical example is unlinking a node from a doubly linked list after its `next` and `prev` pointers have been overwritten: `node->prev->next = node->next` writes an attacker-chosen value to an attacker-chosen address.

## Recommendation

Never read raw external bytes over an in-memory object that contains pointers. Read the data into a separate buffer of plain (non-pointer) fields, validate it, and copy the validated values into the program's own structures. Pointers must only ever be set by the program itself.

## Example

In the following example, data received from a socket is written over `data`, which contains linked list pointers. The subsequent unlink writes through the corrupted pointers:

```c
badStruct data;
linkedList head = { &head, &head };
data.list.next = head.next;
data.list.prev = head.prev;
head.next = &data.list;
head.prev = &data.list;
recv(sock, (char *)&data, sizeof(data), 0);
linkedListPrev = data.list.prev;
linkedListNext = data.list.next;
linkedListPrev->next = linkedListNext; // BAD: write-what-where
linkedListNext->prev = linkedListPrev; // BAD: write-what-where
```

Receive the payload into a structure without pointers instead, and keep the list pointers under the program's control:

```c
struct payload { int id; int value; } msg;
recv(sock, (char *)&msg, sizeof(msg), 0);
/* validate msg, then copy the plain fields into the list node */
```

## References

- CWE-123: [Write-what-where Condition](https://cwe.mitre.org/data/definitions/123.html).
- CWE-787: [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html).
