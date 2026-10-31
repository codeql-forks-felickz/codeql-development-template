# String use after a possibly unterminated copy

Copying bytes into an uninitialized character array without writing a terminator can leave the array unterminated. Passing it to a string operation can read beyond the array.

## Recommendation

Reserve space for and explicitly write a null terminator, or use a bounded operation that guarantees termination.

## Known limitations

This heuristic handles near-full `memcpy`/`memmove` calls into uninitialized local character arrays and recognized string uses. It does not inspect copied source bytes, so it may report when the copied bytes already contain a null terminator.
