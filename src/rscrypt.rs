pub struct Base64;

const BASE64_CHARS: [u8; 64] = [
    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
    b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f',
    b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v',
    b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/',
];

impl Base64 {
    pub fn encode(bytes: &[u8]) -> String {
        let len = bytes.len();
        let mut result = String::with_capacity((len + 2) / 3 * 4);
        for i in (0..len).step_by(3) {
            let c = [
                bytes[i],
                if i + 1 < len { bytes[i + 1] } else { 0 },
                if i + 2 < len { bytes[i + 2] } else { 0 },
            ];
            let index = [
                (c[0] >> 2) as usize,
                (((c[0] & 0b11) << 4) | (c[1] >> 4)) as usize,
                (((c[1] & 0b1111) << 2) | (c[2] >> 6)) as usize,
                (c[2] & 0b111111) as usize,
            ];
            result.push(BASE64_CHARS[index[0]] as char);
            result.push(BASE64_CHARS[index[1]] as char);
            result.push(if i + 1 < len {
                BASE64_CHARS[index[2]]
            } else {
                b'='
            } as char);
            result.push(if i + 2 < len {
                BASE64_CHARS[index[3]]
            } else {
                b'='
            } as char);
        }
        result
    }

    pub fn decode(s: &str) -> Vec<u8> {
        let len = s.len();
        if len % 4 != 0 {
            return Vec::new();
        }
        let mut result = Vec::with_capacity(len / 4 * 3);
        for i in (0..len).step_by(4) {
            let index = [
                BASE64_CHARS
                    .iter()
                    .position(|&c| c == s.as_bytes()[i])
                    .unwrap(),
                BASE64_CHARS
                    .iter()
                    .position(|&c| c == s.as_bytes()[i + 1])
                    .unwrap(),
                if s.as_bytes()[i + 2] == b'=' {
                    0
                } else {
                    BASE64_CHARS
                        .iter()
                        .position(|&c| c == s.as_bytes()[i + 2])
                        .unwrap()
                },
                if s.as_bytes()[i + 3] == b'=' {
                    0
                } else {
                    BASE64_CHARS
                        .iter()
                        .position(|&c| c == s.as_bytes()[i + 3])
                        .unwrap()
                },
            ];
            let c = [
                ((index[0] as u8) << 2) | ((index[1] as u8) >> 4),
                ((index[1] as u8) << 4) | ((index[2] as u8) >> 2),
                ((index[2] as u8) << 6) | (index[3] as u8),
            ];
            result.push(c[0]);
            if s.as_bytes()[i + 2] != b'=' {
                result.push(c[1]);
            }
            if s.as_bytes()[i + 3] != b'=' {
                result.push(c[2]);
            }
        }
        result
    }
}

use rand::{thread_rng, RngCore};
use regex::Regex;
use sha2::{Digest, Sha256};
pub struct Rscrypt;

impl Rscrypt {
    pub fn compare(src: &str, dst: &str) -> bool {
        if !Self::is_valid_hash(dst) {
            return false;
        }
        if let Some(salt) = Self::get_salt(dst) {
            let hashed = Self::hash(&salt, src);
            hashed == dst
        } else {
            false
        }
    }

    pub fn gen_salt(cost: usize) -> String {
        const BASE64_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut salt = format!("$rscrypt${}${}$", env!("CARGO_PKG_VERSION"), cost);
        let mut phrase = vec![0; 16];
        thread_rng().fill_bytes(&mut phrase);

        let rounds = 2u32.pow(cost as u32);
        for _ in 0..rounds {
            let mut hash = Sha256::new();
            hash.update(&phrase);
            phrase = hash.finalize().to_vec();
        }

        let mut index = 0;
        let mut bits = 0;
        for _ in 0..22 {
            if bits < 6 {
                bits += 8;
                index += 1;
            }
            bits -= 6;
            let byte = (phrase[index - 1] >> bits) as usize & 0x3f;
            salt.push(BASE64_CHARS[byte] as char);
        }

        salt
    }

    fn get_cost(salt: &str) -> usize {
        let re = Regex::new(r"\$(\d+)\$").unwrap();
        let caps = re.captures(salt).unwrap();
        let cost = caps[1].parse::<usize>().unwrap();
        cost
    }

    pub fn get_salt(hash: &str) -> Option<String> {
        let re = Regex::new(r"\$rscrypt\$([\d.]+)\$(\d+)\$(.+)").unwrap();
        if let Some(caps) = re.captures(hash) {
            let version = caps.get(1).unwrap().as_str();
            let cost = caps.get(2).unwrap().as_str().parse::<usize>().unwrap();
            let salt = format!("$rscrypt${}${}${}", version, cost, &caps[3]);
            Some(salt)
        } else {
            None
        }
    }

    pub fn hash(salt: &str, unhashed_str: &str) -> String {
        let cost = Rscrypt::get_cost(&salt);
        let rounds = 2u32.pow(cost as u32);
        let mut hashed = String::from(unhashed_str);
        hashed.push_str(&salt);
        for _ in 0..rounds {
            let mut hash = Sha256::new();
            hash.update(hashed.as_bytes());
            hashed = Base64::encode(&hash.finalize());
        }
        hashed.push_str(&salt);
        hashed
    }

    pub fn is_valid_hash(hash: &str) -> bool {
        let re = Regex::new(r"\$rscrypt\$([\d.]+)\$(\d+)\$(.{22})").unwrap();
        re.is_match(hash)
    }
}
