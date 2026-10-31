---
category: newQuery
---
* Added a new query, `rb/insecure-mass-assignment-sensitive-field`, to detect ActiveRecord mass assignment from strong-parameter allowlists that permit ownership or privilege attributes (such as `creator_id`, `user_id` or `admin`). This complements `rb/insecure-mass-assignment`, which only reports arbitrary `permit!`/`to_unsafe_h` flows.
