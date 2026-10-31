# Dereference through a wider pointer type

Casting a pointer to a smaller local object through `void *` and dereferencing it as a wider type can read beyond the object's storage.

## Recommendation

Keep the pointed-to object alive for the entire use and ensure the pointer's target type matches the actual object type. Copy bytes into an object of the destination type when conversion is intended.

## Known limitations

The query handles a direct assignment of a local object's address to a `void *` local and a subsequent wider C-style pointer dereference. It does not attempt to distinguish intentional type punning or track other pointer aliases.
