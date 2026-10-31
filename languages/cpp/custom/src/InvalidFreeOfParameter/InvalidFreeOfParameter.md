# Free of a pointer-to-pointer parameter

Freeing a pointer-to-pointer parameter may release storage owned by the caller, for example when an error path passes the output parameter to `free` instead of freeing the local allocation.

## Recommendation

Free only storage allocated and owned by the current function. For an output parameter, clean up the local allocation and leave the caller's storage untouched.

## Known limitations

This heuristic reports direct `free` calls on pointer-to-pointer parameters. It cannot determine ownership contracts at call sites, so a function that explicitly takes ownership of a heap-allocated pointer-to-pointer may also be reported.
