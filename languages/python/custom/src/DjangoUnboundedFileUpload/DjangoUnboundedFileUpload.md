# Django file upload field without a size validator

This query reports Django model `FileField` and `ImageField` declarations that do not pass an argument recognizable as a file-size validator. Without an upload-size limit, a client can submit a large file and consume application memory or storage.

The query is heuristic and intended for a Community Pack. It only inspects validators passed directly to model fields and recognizes size validators from names containing terms such as `file_size`, `upload_size` or `max_size`. It does not analyze validators defined on forms, model clean methods, upload handlers, aliases for validator lists, or deployment-level request limits. `FILE_UPLOAD_MAX_MEMORY_SIZE` is a memory-spooling threshold, not a maximum upload size.
