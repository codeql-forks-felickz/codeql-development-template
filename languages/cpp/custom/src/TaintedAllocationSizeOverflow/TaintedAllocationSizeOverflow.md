# Integer overflow in allocation size from untrusted data

Computing an allocation size by multiplying an untrusted element count by an element size (for example `malloc(count * sizeof(int))`) can wrap around. When it does, a buffer far smaller than `count` elements is allocated, and code that then initializes or copies `count` elements writes beyond the end of the buffer (CWE-680). A negative count converted to `size_t` is a common way to trigger the wrap.

This query reports multiplications in an allocation size argument that use untrusted data and that range analysis cannot prove to be free of overflow. Unlike `cpp/uncontrolled-allocation-size`, comparisons of the count that occur *after* the allocation (such as the bound of an initialization loop) are not treated as validation.

## Recommendation

Validate the count before computing the size: reject negative values and values greater than `SIZE_MAX / sizeof(element)`, or a smaller application-specific limit. Alternatively, use an allocator that checks the multiplication itself, such as `calloc(count, sizeof(element))` or `reallocarray`.

## Example

In the following example, a count received from a socket is multiplied by `sizeof(int)` without validation. The loop bound comparison happens after the allocation and does not prevent the overflow:

```c
int data = atoi(inputBuffer); /* from recv */
int *intPointer = (int *)malloc(data * sizeof(int)); // BAD: may wrap around
for (size_t i = 0; i < (size_t)data; i++) {
    intPointer[i] = 0; /* heap buffer overflow */
}
```

Check the count first, or let `calloc` perform the checked multiplication:

```c
int data = atoi(inputBuffer);
if (data <= 0 || (size_t)data > SIZE_MAX / sizeof(int)) {
    return;
}
int *intPointer = (int *)malloc(data * sizeof(int)); // GOOD: cannot wrap
```

## References

- CWE-680: [Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html).
- CWE-190: [Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html).
- CWE-131: [Incorrect Calculation of Buffer Size](https://cwe.mitre.org/data/definitions/131.html).
