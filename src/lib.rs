use rand::Rng;
use regex::Regex;
use sha2::{Digest, Sha256};

static BASE64_CHARS: &'static [u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static INDEX_TABLE: [u8; 128] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
    255, 255, 255, 255, 255, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 255, 255, 255, 255, 255, 255, 28, 29, 30, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 255, 255, 255, 255, 255,
];

/**
[decode]
 */
/**
Decode a base64 string into a byte vector.
*/
///
/// # Examples
///
/// ```
/// use rscrypt::decode;
///
/// decode(base64_string);
/// ```
pub fn decode(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len() * 3 / 4);
    let mut i = 0;
    let mut n = 0;
    let mut l = 0;
    let mut count = 0;
    while i < src.len() {
        let b = INDEX_TABLE[src[i] as usize];
        i += 1;
        if b == 255 {
            continue;
        }
        count += 1;
        n |= b as u32;
        if count == 4 {
            count = 0;
            dst.push((n >> 16) as u8);
            dst.push((n >> 8) as u8);
            dst.push(n as u8);
            n = 0;
        } else {
            n <<= 6;
        }
        l += 1;
        if l == 4 {
            l = 0;
        }
    }
    if count > 0 {
        dst.push((n >> 16) as u8);
        if count == 3 {
            dst.push((n >> 8) as u8);
        }
    }
    dst
}

/**
[encode]
 */
/**
Encode a byte vector into a base64 string.
*/
///
/// # Examples
///
/// ```
/// use rscrypt::encode;
///
/// encode(byte_vec);
/// ```
pub fn encode(src: &[u8]) -> String {
    let mut dst = String::with_capacity(src.len() * 4 / 3);
    let mut i = 0;
    let mut n = 0;
    let mut l = 0;
    while i < src.len() {
        let b = src[i];
        i += 1;
        n |= (b as u32) << (l * 8);
        l += 1;
        if l == 3 {
            l = 0;
            dst.push(BASE64_CHARS[(n >> 18) as usize].clone() as char);
            dst.push(BASE64_CHARS[((n >> 12) & 0x3f) as usize].clone() as char);
            dst.push(BASE64_CHARS[((n >> 6) & 0x3f) as usize].clone() as char);
            dst.push(BASE64_CHARS[(n & 0x3f) as usize].clone() as char);
            n = 0;
        }
    }
    if l > 0 {
        let n = n << (6 * (3 - l));
        dst.push(BASE64_CHARS[(n >> 18) as usize].clone() as char);
        dst.push(BASE64_CHARS[((n >> 12) & 0x3f) as usize].clone() as char);
        if l == 1 {
            dst.push('=');
        } else {
            dst.push(BASE64_CHARS[((n >> 6) & 0x3f) as usize].clone() as char);
            dst.push('=');
        }
    }
    dst
}

/**
[gen_salt]
 */
/**
Generates a salt of the given length.
*/
///
/// # Examples
///
/// ```
/// use rscrypt::gen_salt;
///
/// gen_salt(length);
/// ```
pub fn gen_salt(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut salt = String::new();
    salt.push_str("$");
    salt.push_str(&len.to_string());
    salt.push_str("$");

    for n in 0..len {
        if n % 3 == 0 {
            salt.push(rng.gen_range(b'0'..b'9') as char);
        } else {
            salt.push(rng.gen_range(b'a'..b'z') as char);
        }
    }
    salt
}
/**
[get_salt]
 */
/**
Extracts the salt from a hashed string
*/
///
/// # Examples
///
/// ```
/// use rscrypt::get_salt;
///
/// get_salt(hashed);
/// ```
pub fn get_salt(hash: &str) -> String {
    let re = Regex::new(r"\$(\d+)\$(.+)").unwrap();
    let caps = re.captures(hash).unwrap();
    let salt = format!("{}{}{}{}", "$", &caps[1], "$", &caps[2]);
    salt.to_string()
}

/**
[hash]
 */
/**
Hashes the salt with the given string and return a hashed string
*/
///
/// # Examples
///
/// ```
/// use rscrypt::{hash, gen_salt};
///
/// let salt = gen_salt(10);
/// hash(salt, unhashed_str);
/// ```
pub fn hash(salt: &str, unhashed_str: &str) -> String {
    let mut hasher = Sha256::new();
    let mut hashed = String::new();
    let mut unhashed = String::new();
    unhashed.push_str(salt);
    unhashed.push_str(unhashed_str);
    hasher.update(unhashed.as_bytes());
    hashed.push_str(&encode(&hasher.finalize()));
    hashed.push_str(&salt);
    hashed
}

/**
[compare]
 */
/**
Compares an unhashed string with a hashed string and return a boolean
*/
///
/// # Examples
///
/// ```
/// use rscrypt::compare;
///
/// let result = compare(unhashed, hashed);
/// ```
pub fn compare(src: &str, dst: &str) -> bool {
    let salt = get_salt(dst);
    let hashed = hash(&salt, src);
    hashed == dst
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode() {
        let src = b"Hello World";
        let dst = encode(src);
        assert_eq!(dst, "SGVsbG8gV29ybGQ=");
    }
    #[test]
    fn test_decode() {
        let src = "SGVsbG8gV29ybGQ=";
        let dst = decode(src.as_bytes());
        assert_eq!(dst, b"Hello World");
    }
    #[test]
    fn test_gen_salt() {
        let salt = gen_salt(16);
        assert_eq!(salt.len(), 20);
    }
    #[test]
    fn test_hash() {
        let salt = gen_salt(16);
        let password = "password";
        let hashed = hash(&salt, password);
        assert_eq!(hashed.len(), 64);
    }
    #[test]
    fn test_compare() {
        let salt = gen_salt(16);
        let password = "password";
        let hashed = hash(&salt, password);
        assert!(compare(password, &hashed));
    }
}
