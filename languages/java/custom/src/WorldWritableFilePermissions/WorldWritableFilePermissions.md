# World-writable file permissions

Making a file writable by all users (for example `chmod 777`, `chmod o+w`, `File.setWritable(true, false)` or a POSIX permission set that contains `OTHERS_WRITE`) lets any local user modify or replace it. If the file is a script or program that the application later runs, or configuration that it later reads, another user on the same host can execute code or change behavior as the application user. Files in shared temporary directories are especially exposed.

## Recommendation

Grant only the permissions that are needed, normally to the owner only (for example `chmod 700` or `PosixFilePermissions.fromString("rwx------")`). Create sensitive files in a private directory rather than a shared temporary directory, and set restrictive permissions when the file is created.

## Example

```java
runtime.exec("chmod 777 " + script.getAbsolutePath());   // BAD
runtime.exec("chmod 700 " + script.getAbsolutePath());   // GOOD
```

## References

- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CERT FIO01-J: Create files with appropriate access permissions](https://wiki.sei.cmu.edu/confluence/display/java/FIO01-J.+Create+files+with+appropriate+access+permissions)
