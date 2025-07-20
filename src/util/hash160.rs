use sha2::{Sha256, Digest as ShaDigest};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use std::fmt;
use zeroize::Zeroize;

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

pub fn hash160(data: &[u8]) -> Hash160 {
    if data.len() > 520 { // BSV script max
        panic!("Input too large for hash160");
    }
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut hash160 = [0; 20];
    hash160.copy_from_slice(&ripemd);
    Hash160(hash160)
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Zeroize for Hash160 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Hash160 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn tohash160() {
        let pubkey = "126999eabe3f84a3a9f5c09e87faab27484818a0ec1d67b94c9a02e40268499d98538cf770198550adfb9d1d473e5e926bb00e4c58baec1fb42ffa6069781003e4";
        let pubkey = hex::decode(pubkey).unwrap();
        assert!(hex::encode(hash160(&pubkey).0) == "3c231b5e624a42e99a87160c6e4231718a6d77c0");
    }

    #[test]
    fn test_from_array() {
        let bytes = [0u8; 20];
        let hash160: Hash160 = bytes.into();
        assert_eq!(hash160.0, bytes);
    }

    #[test]
    #[should_panic]
    fn test_large_input() {
        let data = vec![0u8; 521];
        hash160(&data);
    }
}
