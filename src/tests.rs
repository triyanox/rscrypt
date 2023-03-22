#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode() {
        let src = b"Hello World";
        let dst = Base64::encode(src);
        assert_eq!(dst, "SGVsbG8gV29ybGQ=");
    }
    #[test]
    fn test_decode() {
        let src = "SGVsbG8gV29ybGQ=";
        let dst = Base64::decode(src);
        assert_eq!(dst, b"Hello World");
    }
    #[test]
    fn test_compare() {
        let salt = gen_salt(16);
        let password = "password@8881((!jjda___$";
        let hashed = hash(&salt, password);
        assert!(compare(password, &hashed));
    }
}
