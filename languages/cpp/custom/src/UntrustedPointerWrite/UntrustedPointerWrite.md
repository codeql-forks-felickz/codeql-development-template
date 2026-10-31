# Write through a pointer read from untrusted data

## Overview

Untrusted input is read directly over memory that contains pointers (for example `fgets((char *)&data, sizeof(data), stdin)` where `data` contains linked-list pointers), and one of those pointers is later written through, as in an unlink operation `prev->next = next`. An attacker controls both the address and the value of the write, a "write-what-where" condition that typically leads to arbitrary code execution.

## Recommendation

Never read untrusted data over memory that contains pointers. Read the input into a separate byte buffer and parse the fields that are needed, and validate pointers or indexes before using them.

## Example

```c
void bad(void) {
  badStruct data;
  /* ... link data.list into a list ... */
  fgets((char *)&data, sizeof(data), stdin);
  data.list.prev->next = data.list.next; // BAD: attacker controls prev and next
}

void good(void) {
  badStruct data;
  char input[100];
  /* ... link data.list into a list ... */
  fgets(input, sizeof(input), stdin);
  data.list.prev->next = data.list.next; // GOOD: list pointers were not overwritten
}
```

## References

- MITRE CWE: [CWE-123: Write-what-where Condition](https://cwe.mitre.org/data/definitions/123.html).
- MITRE CWE: [CWE-822: Untrusted Pointer Dereference](https://cwe.mitre.org/data/definitions/822.html).
