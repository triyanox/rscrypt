# 🔑 rscrypt

[![Rate this package](https://badges.openbase.com/rust/rating/rscrypt.svg?style=openbase&token=DXzSYfymfIyxGQ7pnKTwNfu6L/6K/eL/yFVW09TDw8o=)](https://openbase.com/rust/rscrypt?utm_source=embedded&utm_medium=badge&utm_campaign=rate-badge)

rscrypt is a simple, fast, and secure encryption tool written in Rust.

# Usage

Add rscrypt to your Cargo.toml:

```toml
[dependencies]
rscrypt = "*"
```

or install via cargo

```bash
cargo add rscrypt
```

# Features

**rscrypt** contains simple functions for encrypting and decrypting data.

- `gen_salt`: Generates a random salt.
- `get_salt`: Extracts the salt from the hashed string.
- `get_cost`: Extracts the cost from the salt.
- `hash`: Hashes a string with a salt.
- `encode`: Encodes a string to base64.
- `decode`: Decodes a base64 string.
- `compare`: compare a string to a hashed string.

# Example

```rust
use rscrypt::{gen_salt, hash, compare};

fn main() {
    let salt = gen_salt(10);
    let hash = hash(&salt, "password");
    let is_correct = compare("password", &hash);
    println!("{}", is_correct);
}
```
