---
category: newQuery
---
* Added a new query, `rb/path-injection-dynamic-constructor`, which extends `rb/path-injection` to treat the first argument to `new` on a dynamically resolved class (`constantize`, `safe_constantize`, `const_get`) as a filesystem path. This detects path traversal such as `send_file params[:type].constantize.new(params[:name])`, where the attacker can choose `File` as the class.
