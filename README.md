# cmpdt

Compare directory trees

```rust
use std::path::PathBuf;
use cmpdt::cmp_ftree_sync;

let cmp = PathBuf::from("...");
let against = PathBuf::from("...");
let result = cmp_ftree_sync(against, cmp);

println!("{result:#?}");
```
