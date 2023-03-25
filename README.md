# 🔑 rscrypt

[![Rate this package](https://badges.openbase.com/rust/rating/rscrypt.svg?style=openbase&token=jegmjYAyM4kvHND4ASaphN2tpYqF1XfW7e+HedvxkVA=)](https://openbase.com/rust/rscrypt?utm_source=embedded&amp;utm_medium=badge&amp;utm_campaign=rate-badge)

The `Rscrypt` library provides functionality for creating and verifying password hashes.

## 🚀 Installation

To use the `rscrypt` library in your Rust project, add it as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
rscrypt = "*"
```

Then, run `cargo build` to download and compile the dependencies.

Alternatively, you can use the following command for adding the latest version of the library:

```shell
cargo add rscrypt
```

Once installed, you can import the library in your Rust code using:

```rust
use rscrypt::{ Rscrypt };
```

That's it! You're ready to use the `rscrypt` library in your Rust project.

## 🏗️ Struct `Rscrypt`

This struct provides the following utility functions:

### 🔎 Function `compare(src: &str, dst: &str) -> bool`

This function compares the plaintext password string `src` with the hashed password string `dst`. It returns `true` if they match, else `false`.

```rust
use rscrypt::{Rscrypt};

let salt = Rscrypt::gen_salt(10);
let hashed = Rscrypt::hash(&salt, "password");
assert!(Rscrypt::compare("password", &hash));
```

### 🔒 Function `gen_salt(cost: usize) -> String`

This function generates a random salt value that can be used for hashing a password. The `cost` argument determines the number of computational rounds to perform during hashing.

```rust
use rscrypt::{Rscrypt};

let salt = Rscrypt::gen_salt(10);
let hashed = Rscrypt::hash(&salt, "password");
assert!(Rscrypt::compare("password", &hashed));
```

### 🔍 Function `get_salt(hash: &str) -> Option<String>`

This function extracts the salt value used for hashing from the given `hash` string.

```rust
use rscrypt::{Rscrypt};

let hash = "iIBDWiEk0118e29VbozxVmoCscUzu6k05cKGFbtgogI=$rscrypt$0.2.0$10$rLBARHBrWKCsvACVvBAN7O";
let salt = Rscrypt::get_salt(&hash);
assert_eq!(salt, "$rscrypt$0.2.0$10$rLBARHBrWKCsvACVvBAN7O");
```

### 🚀 Function `hash(salt: &str, unhashed_str: &str) -> String`

This function hashes the plaintext password string `unhashed_str` with the given salt value `salt`.

```rust
use rscrypt::{Rscrypt};

let hashed = Rscrypt::hash("$rscrypt$0.2.0$10$rLBARHBrWKCsvACVvBAN7O", "password");
assert_eq!(
    hashed,
    "iIBDWiEk0118e29VbozxVmoCscUzu6k05cKGFbtgogI=$rscrypt$0.2.0$10$rLBARHBrWKCsvACVvBAN7O"
);
```

### 🕵️‍♀️ Function `is_valid_hash(hash: &str) -> bool`

This function returns `true` if the given hash string is a valid hashed password string, else `false`.

```rust
use rscrypt::{Rscrypt};

let hash = "iIBDWiEk0118e29VbozxVmoCscUzu6k05cKGFbtgogI=$rscrypt$0.2.0$10$rLBARHBrWKCsvACVvBAN7O";
assert!(Rscrypt::is_valid_hash(&hash));
```

## 📝 License

This project is licensed under the [MIT License](LICENSE).
