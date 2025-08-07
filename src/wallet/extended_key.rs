use crate::network::Network;
use crate::util::{sha256d, Error, Result, Serializable};
use base58::{ToBase58, FromBase58};
use ring::digest::{digest, SHA256};
use ring::hmac as ring_hmac;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::io::{self, Read, Write};
use std::fmt;

// Version bytes for extended keys
pub const MAINNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
pub const MAINNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E]; // xpub
pub const TESTNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // tprv
pub const TESTNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x87, 0xCF]; // tpub
pub const HARDENED_KEY: u32 = 0x80000000;

/// Type of extended key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyType {
    Private,
    Public,
}

/// Represents a BIP-32 extended key (private or public)
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Returns the version bytes
    pub fn version(&self) -> [u8; 4] {
        let mut version = [0u8; 4];
        version.copy_from_slice(&self.0[0..4]);
        version
    }

    /// Returns the depth of the key
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Returns the parent fingerprint
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&self.0[5..9]);
        fingerprint
    }

    /// Returns the child number
    pub fn child_number(&self) -> u32 {
        u32::from_be_bytes(self.0[9..13].try_into().unwrap())
    }

    /// Returns the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Returns the key data (private key or public key)
    pub fn key(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.0[45..78]);
        key
    }

    /// Checks if the key is private
    pub fn is_private(&self) -> bool {
        let version = self.version();
        version == MAINNET_PRIVATE_EXTENDED_KEY || version == TESTNET_PRIVATE_EXTENDED_KEY
    }

    /// Encodes an extended key into a base58 string
    pub fn encode(&self) -> String {
        let checksum = sha256d(&self.0);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        v.to_base58()
    }

    /// Decodes an extended key from a base58 string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = s.from_base58().map_err(|e| Error::FromBase58Error(e))?;
        if v.len() != 82 {
            return Err(Error::BadData("Invalid extended key length".to_string()));
        }
        let checksum = sha256d(&v[..78]);
        if checksum.0[..4] != v[78..] {
            return Err(Error::BadData("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.copy_from_slice(&v[..78]);
        Ok(extended_key)
    }

    /// Derives a child key (hardened or normal)
    pub fn derive_child(&self, index: u32, secp: &Secp256k1<secp256k1::All>) -> Result<ExtendedKey> {
        let is_private = self.is_private();
        let is_hardened = index >= HARDENED_KEY;

        // Prepare HMAC input
        let mut hmac_input = vec![0u8; 37]; // Pre-allocate 37 bytes for private or 38 for public
        if is_private && is_hardened {
            hmac_input[0] = 0;
            let private_key = &self.key()[1..33]; // Private key without prefix
            eprintln!("Full key data: {} (len: {})", hex::encode(self.key()), self.key().len());
            eprintln!("Private key bytes: {:?} (len: {})", private_key, private_key.len());
            if private_key.len() != 32 {
                return Err(Error::BadData(format!("Invalid private key length: {}", private_key.len())));
            }
            hmac_input[1..33].copy_from_slice(&private_key[..32]);
            hmac_input[33..37].copy_from_slice(&index.to_be_bytes());
            eprintln!("HMAC input bytes: {:?} (len: {})", hmac_input, hmac_input.len());
        } else if is_private {
            let pubkey = PublicKey::from_secret_key(secp, &SecretKey::from_byte_array(&self.key()[1..33])?);
            eprintln!("Using public key: {} (len: {})", hex::encode(pubkey.serialize()), pubkey.serialize().len());
            hmac_input = vec![0u8; 37]; // Public key is 33 bytes
            hmac_input[0..33].copy_from_slice(&pubkey.serialize());
            hmac_input[33..37].copy_from_slice(&index.to_be_bytes());
            eprintln!("HMAC input bytes: {:?} (len: {})", hmac_input, hmac_input.len());
        } else {
            if is_hardened {
                return Err(Error::InvalidOperation("Hardened derivation not supported for public keys".to_string()));
            }
            eprintln!("Using public key: {} (len: {})", hex::encode(self.key()), self.key().len());
            hmac_input = vec![0u8; 37]; // Public key is 33 bytes
            hmac_input[0..33].copy_from_slice(&self.key());
            hmac_input[33..37].copy_from_slice(&index.to_be_bytes());
            eprintln!("HMAC input bytes: {:?} (len: {})", hmac_input, hmac_input.len());
        }

        // Compute input checksum
        let input_checksum = digest(&SHA256, &hmac_input);
        eprintln!("HMAC input checksum: {}", hex::encode(input_checksum.as_ref()));

        // Compute HMAC using ring
        let chain_code = self.chain_code();
        let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, &chain_code);
        let result = ring_hmac::sign(&hmac_key, &hmac_input);
        let result_bytes = result.as_ref();
        eprintln!("Raw HMAC result: {} (len: {})", hex::encode(result_bytes), result_bytes.len());
        if result_bytes.len() != 64 {
            return Err(Error::BadData(format!("Invalid HMAC output length: {}", result_bytes.len())));
        }
        let il: [u8; 32] = result_bytes[0..32].try_into().unwrap();
        let new_chain_code: [u8; 32] = result_bytes[32..64].try_into().unwrap();
        eprintln!("HMAC output il: {}", hex::encode(&il));
        eprintln!("HMAC output chain_code: {}", hex::encode(&new_chain_code));

        let mut child_key = ExtendedKey([0; 78]);
        // Set version bytes (same as parent for private keys)
        child_key.0[0..4].copy_from_slice(&self.version());
        // Increment depth
        child_key.0[4] = self.depth().wrapping_add(1);
        // Compute parent fingerprint
        let parent_pubkey = if is_private {
            PublicKey::from_secret_key(secp, &SecretKey::from_slice(&self.key()[1..33])?)
        } else {
            PublicKey::from_slice(&self.key())?
        };
        let parent_fingerprint: [u8; 4] = sha256d(&parent_pubkey.serialize()).0[..4].try_into().unwrap();
        child_key.0[5..9].copy_from_slice(&parent_fingerprint);
        // Set child index
        child_key.0[9..13].copy_from_slice(&index.to_be_bytes());
        // Set chain code
        child_key.0[13..45].copy_from_slice(&new_chain_code);

        // Compute child key
        if is_private {
            let parent_secret = SecretKey::from_slice(&self.key()[1..33])?;
            let tweak = SecretKey::from_slice(&il).map_err(|e| Error::BadData(format!("Invalid tweak: {}", e)))?;
            let child_secret = parent_secret.add_tweak(&tweak.into()).map_err(|e| Error::BadData(format!("Tweak failed: {}", e)))?;
            child_key.0[45] = 0; // Private key prefix
            child_key.0[46..78].copy_from_slice(&child_secret[..]);
            eprintln!("Parent private key: {}", hex::encode(&self.key()[1..33]));
            eprintln!("Tweak: {}", hex::encode(&il));
            eprintln!("Child private key: {}", hex::encode(&child_secret[..]));
        } else {
            let pubkey = PublicKey::from_slice(&self.key())?;
            let tweak = SecretKey::from_slice(&il).map_err(|e| Error::BadData(format!("Invalid tweak: {}", e)))?;
            let child_pubkey = pubkey.add_exp_tweak(secp, &tweak.into()).map_err(|e| Error::BadData(format!("Tweak failed: {}", e)))?;
            child_key.0[45..78].copy_from_slice(&child_pubkey.serialize());
        }

        eprintln!("Child key bytes: {:?}", child_key.0);
        Ok(child_key)
    }
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut data = [0u8; 78];
        reader.read_exact(&mut data)?;
        Ok(ExtendedKey(data))
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExtendedKey({})", self.encode())
    }
}

/// Derives an extended key from a seed or parent key
pub fn derive_extended_key(
    input: &str,
    path: &str,
    network: Network,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<ExtendedKey> {
    if path.is_empty() || path == "m" {
        let seed = hex::decode(input).map_err(|_| Error::BadData("Invalid hex seed".to_string()))?;
        return extended_key_from_seed(&seed, network);
    }

    let mut key = ExtendedKey::decode(input)?;
    let path_parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
    for part in path_parts {
        let is_hardened = part.ends_with('H') || part.ends_with('\'');
        let index_str = part.trim_end_matches(|c| c == 'H' || c == '\'');
        let index: u32 = index_str
            .parse()
            .map_err(|_| Error::BadData("Invalid derivation index".to_string()))?;
        let index = if is_hardened { index + HARDENED_KEY } else { index };
        key = key.derive_child(index, secp)?;
    }
    Ok(key)
}

/// Creates an extended private key from a seed
pub fn extended_key_from_seed(seed: &[u8], network: Network) -> Result<ExtendedKey> {
    let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, b"Bitcoin seed");
    let result = ring_hmac::sign(&hmac_key, seed);
    let result_bytes = result.as_ref();
    if result_bytes.len() != 64 {
        return Err(Error::BadData(format!("Invalid HMAC output length: {}", result_bytes.len())));
    }

    let secret_key = SecretKey::from_slice(&result_bytes[0..32])?;
    let chain_code = &result_bytes[32..64];

    let mut key = ExtendedKey([0; 78]);
    let version = match network {
        Network::Mainnet => MAINNET_PRIVATE_EXTENDED_KEY,
        Network::Testnet | Network::STN => TESTNET_PRIVATE_EXTENDED_KEY,
    };
    key.0[0..4].copy_from_slice(&version);
    key.0[4] = 0;
    key.0[5..9].copy_from_slice(&[0; 4]);
    key.0[9..13].copy_from_slice(&[0; 4]);
    key.0[13..45].copy_from_slice(chain_code);
    key.0[45] = 0;
    key.0[46..78].copy_from_slice(&secret_key[..]);

    eprintln!("Master private key: {}", hex::encode(&secret_key[..]));
    eprintln!("Master chain_code: {}", hex::encode(chain_code));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac() -> Result<()> {
        let key = hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")?;
        // Hardcoded 32-byte private key
        let private_key = [
            232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197,
            178, 20, 49, 56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
        ];
        eprintln!("Private key bytes: {:?} (len: {})", private_key, private_key.len());
        let index = 0x80000000u32; // Hardened index
        let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
        data[0] = 0;
        data[1..33].copy_from_slice(&private_key[..32]);
        data[33..37].copy_from_slice(&index.to_be_bytes());
        eprintln!("HMAC key bytes: {:?} (len: {})", key, key.len());
        eprintln!("HMAC data bytes: {:?} (len: {})", data, data.len());
        assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

        // Compute input checksum
        let input_checksum = digest(&SHA256, &data);
        eprintln!("HMAC input checksum: {}", hex::encode(input_checksum.as_ref()));

        // Compute HMAC with ring
        let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, &key);
        let result = ring_hmac::sign(&hmac_key, &data[..37]);
        let result_bytes = result.as_ref();
        eprintln!("HMAC result: {} (len: {})", hex::encode(result_bytes), result_bytes.len());

        assert_eq!(
            hex::encode(result_bytes),
            "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let key = extended_key_from_seed(&seed, Network::Testnet)?;
        let encoded = key.encode();
        let decoded = ExtendedKey::decode(&encoded)?;
        assert_eq!(key, decoded);
        Ok(())
    }

    #[test]
    fn test_path() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let master = extended_key_from_seed(&seed, Network::Testnet)?;
        let secp = Secp256k1::new();

        let child = master.derive_child(HARDENED_KEY, &secp)?; // m/0H
        let encoded = child.encode();
        assert_eq!(
            encoded,
            "tprv8dRs2KikLW2c37FPa3Vxkefo3x8zENMRVfCuDUYRoM9zGG1EDh4cUM6TxM58uWDp76on4HdnWUrFrRNYK2Xhhq4gP5RV5CozT2iUMTquXEy"
        );
        Ok(())
    }

    #[test]
    fn test_pubkey() -> Result<()> {
        let secp = Secp256k1::new();
        let private_key = hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")?;
        eprintln!("Decoded private key: {:?} (len: {})", private_key, private_key.len());
        if private_key.len() != 32 {
            return Err(Error::BadData(format!("Invalid private key length: {}", private_key.len())));
        }
        let secret_key = SecretKey::from_slice(&private_key)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        eprintln!("Public key: {}", hex::encode(public_key.serialize()));
        Ok(())
    }

    #[test]
    fn test_hmac_manual() -> Result<()> {
        let key = hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")?;
        // Hardcoded 32-byte private key
        let private_key = [
            232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197,
            178, 20, 49, 56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
        ];
        eprintln!("Private key bytes: {:?} (len: {})", private_key, private_key.len());
        let index = 0x80000000u32;
        let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
        data[0] = 0;
        data[1..33].copy_from_slice(&private_key[..32]);
        data[33..37].copy_from_slice(&index.to_be_bytes());
        eprintln!("HMAC key bytes: {:?} (len: {})", key, key.len());
        eprintln!("HMAC data bytes: {:?} (len: {})", data, data.len());
        assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

        // Compute input checksum
        let input_checksum = digest(&SHA256, &data);
        eprintln!("HMAC input checksum: {}", hex::encode(input_checksum.as_ref()));

        // Compute HMAC with ring
        let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, &key);
        let result = ring_hmac::sign(&hmac_key, &data[..37]);
        let result_bytes = result.as_ref();
        eprintln!("HMAC result: {} (len: {})", hex::encode(result_bytes), result_bytes.len());

        assert_eq!(
            hex::encode(result_bytes),
            "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        Ok(())
    }
}
