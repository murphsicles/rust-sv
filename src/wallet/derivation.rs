// Implements BIP32

pub use ring::hmac as ring_hmac;
pub use sha2::{Digest, Sha256};
pub use secp256k1::{Secp256k1, SecretKey, PublicKey};
use base58::{FromBase58,ToBase58};
use ripemd::Ripemd160;
pub use crate::network::Network;
pub use crate::util::Error;

pub mod constants {
    pub const HARDENED_KEY_OFFSET: u32 = 0x80000000;
}

#[derive(Debug, PartialEq)]
pub enum ExtendedKeyType {
    Private,
    Public,
}
#[derive(Debug, Clone, PartialEq)]
pub struct ExtendedKeypair {
    pub extended_private_key: String,
    pub extended_public_key: String, 
}

impl ExtendedKeypair {
    // Constructor for creating an ExtendedKeypair
    pub fn new(extended_private_key: String, extended_public_key: String) -> Self {
        ExtendedKeypair {
            extended_private_key,
            extended_public_key,
        }
    }

    // Encode the keypair (e.g., return xprv/tprv or xpub/tpub based on network and type)
    pub fn encode(&self, is_private: bool) -> &str {
        if is_private {
            &self.extended_private_key
        } else {
            &self.extended_public_key
        }
    }

    // Decode from a string (xprv/tprv or xpub/tpub)
    pub fn decode(s: &str, network: Network) -> Result<Self, Error> {
        // Validate the key and network, then construct the keypair
        // This is a placeholder; actual decoding depends on your serialization format
        if s.starts_with("xprv") && network == Network::Mainnet {
            Ok(ExtendedKeypair {
                extended_private_key: s.to_string(),
                extended_public_key: String::new(), // Compute xpub if needed
            })
        } else if s.starts_with("tprv") && network == Network::Testnet {
            Ok(ExtendedKeypair {
                extended_private_key: s.to_string(),
                extended_public_key: String::new(), // Compute tpub if needed
            })
        } else if s.starts_with("xpub") && network == Network::Mainnet {
            Ok(ExtendedKeypair {
                extended_private_key: String::new(),
                extended_public_key: s.to_string(),
            })
        } else if s.starts_with("tpub") && network == Network::Testnet {
            Ok(ExtendedKeypair {
                extended_private_key: String::new(),
                extended_public_key: s.to_string(),
            })
        } else {
            Err(Error::Bip32Error("Invalid extended key or network mismatch".to_string()))
        }
    }

    // Get version bytes for serialization based on the extended key string
    pub fn get_version_bytes(extended_key: &str) -> Result<[u8; 4], Error> {
        match extended_key {
            s if s.starts_with("xprv") => Ok([0x04, 0x88, 0xad, 0xe4]), // xprv (Mainnet, private)
            s if s.starts_with("xpub") => Ok([0x04, 0x88, 0xb2, 0x1e]), // xpub (Mainnet, public)
            s if s.starts_with("tprv") => Ok([0x04, 0x35, 0x83, 0x94]), // tprv (Testnet, private)
            s if s.starts_with("tpub") => Ok([0x04, 0x35, 0x87, 0xcf]), // tpub (Testnet, public)
            _ => Err(Error::Bip32Error("Invalid extended key prefix".to_string())),
        }
    }

    // Set version bytes for serialization
    pub fn set_version_bytes(network: Network, is_private: bool) -> [u8; 4] {
        match (network, is_private) {
            (Network::Mainnet, true) => [0x04, 0x88, 0xad, 0xe4], // xprv
            (Network::Mainnet, false) => [0x04, 0x88, 0xb2, 0x1e], // xpub
            (Network::Testnet, true) => [0x04, 0x35, 0x83, 0x94], // tprv
            (Network::Testnet, false) => [0x04, 0x35, 0x87, 0xcf], // tpub
            (Network::STN, true) => [0x04, 0x35, 0x83, 0x94], // tprv
            (Network::STN, false) => [0x04, 0x35, 0x87, 0xcf], // tpub
        }
    }
}

/// Computes double SHA-256 hash (used for checksum)
fn sha256d(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

/// Represents a BIP-32 extended key (private or public) as a simple 78 character long string
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Converts an ExtendedKey String to a Bip32Key Object
    pub fn to_bip32_keyobject(&self) -> Result<Bip32Key, Error> {
        let secp = Secp256k1::new();

        // Extract components from the 78-byte array
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        let depth = self.0[4];
        let parent_fingerprint: [u8; 4] = self.0[5..9].try_into().map_err(|_| {
            Error::Bip32Error("Invalid parent fingerprint length".to_string())
        })?;
        let index: [u8; 4] = self.0[9..13].try_into().map_err(|_| {
            Error::Bip32Error("Invalid index length".to_string())
        })?;
        let chain_code: [u8; 32] = self.0[13..45].try_into().map_err(|_| {
            Error::Bip32Error("Invalid chain code length".to_string())
        })?;
        let key_data: [u8; 33] = self.0[45..78].try_into().map_err(|_| {
            Error::Bip32Error("Invalid key data length".to_string())
        })?;

        // Determine network and key type from version bytes
        let (network, is_private) = match version {
            [0x04, 0x88, 0xAD, 0xE4] => (Network::Mainnet, true),  // xprv
            [0x04, 0x88, 0xB2, 0x1E] => (Network::Mainnet, false), // xpub
            [0x04, 0x35, 0x83, 0x94] => (Network::Testnet, true),  // tprv
            [0x04, 0x35, 0x87, 0xCF] => (Network::Testnet, false), // tpub
            _ => return Err(Error::Bip32Error("Invalid version bytes".to_string())),
        };

        // Parse key data
        let (private_key, public_key) = if is_private {
            // For private keys, expect 0x00 followed by 32-byte private key
            if key_data[0] != 0 {
                return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
            }
            let secret_key_bytes: [u8; 32] = key_data[1..33].try_into().map_err(|_| {
                Error::Bip32Error("Invalid private key length: expected 32 bytes".to_string())
            })?;
            let secret_key = SecretKey::from_byte_array(secret_key_bytes).map_err(|e| {
                Error::Bip32Error(format!("Invalid private key: {}", e))
            })?;
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            (Some(secret_key), public_key)
        } else {
            // For public keys, expect 33-byte compressed public key
            let public_key = PublicKey::from_slice(&key_data).map_err(|e| {
                Error::Bip32Error(format!("Invalid public key: {}", e))
            })?;
            (None, public_key)
        };

        Ok(Bip32Key {
            private_key,
            public_key,
            network,
            version,
            chain_code,
            parent_fingerprint,
            depth,
            index,
        })
    }

    /// Returns the key data (private key or public key)
    pub fn key(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.0[45..78]);
        key
    }

    /// Returns boolean if the key is private or not
    pub fn is_private(&self) -> Result<bool, Error> {
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        
        match version {
            [0x04, 0x88, 0xAD, 0xE4] => Ok(true),  // xprv
            [0x04, 0x35, 0x83, 0x94] => Ok(true),  // tprv
            [0x04, 0x88, 0xB2, 0x1E] => Ok(false), // xpub
            [0x04, 0x35, 0x87, 0xCF] => Ok(false), // tpub
            _ => Err(Error::Bip32Error("Invalid version bytes".to_string())),
        }
    }

    /// Returns network type and Extended Key Type
    pub fn check_keytype(&self) -> Result<(Network, ExtendedKeyType), Error> {
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        
        match version {
            [0x04, 0x88, 0xAD, 0xE4] => Ok((Network::Mainnet, ExtendedKeyType::Private)),  // xprv
            [0x04, 0x88, 0xB2, 0x1E] => Ok((Network::Mainnet, ExtendedKeyType::Public)),   // xpub
            [0x04, 0x35, 0x83, 0x94] => Ok((Network::Testnet, ExtendedKeyType::Private)),  // tprv
            [0x04, 0x35, 0x87, 0xCF] => Ok((Network::Testnet, ExtendedKeyType::Public)),   // tpub
            _ => Err(Error::Bip32Error("Invalid version bytes".to_string())),
        }
    }

    /// Encodes an extended key into a base58 string
    pub fn encode(&self) -> Result<String, Error> {
        base58_check_encode(&self.0)
    }


    /// Decodes an extended key from a base58 string
    pub fn decode(s: &str) -> Result<ExtendedKey, Error> {
        let data = s.from_base58().map_err(|e| Error::Bip32Error(format!("Base58 decode error: {:?}", e)))?;
        if data.len() != 82 {
            return Err(Error::Bip32Error(format!("Invalid extended key length: {}", data.len())));
        }
        let payload = &data[..78];
        let checksum = &data[78..82];
        let computed_checksum = sha256d(payload);
        if checksum != &computed_checksum[..4] {
            return Err(Error::Bip32Error("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.copy_from_slice(payload);
        Ok(extended_key)
    }

    
    pub fn get_private_key(xprv: &str) -> Result<[u8; 32], Error> {
        let decoded = xprv.from_base58()
            .map_err(|e| Error::Bip32Error(format!("Base58 decode error: {:?}", e)))?;

        if decoded.len() != 82 {
            return Err(Error::Bip32Error(format!("Invalid extended key length: {}", decoded.len())));
        }
        
        let payload = &decoded[..78];
        let checksum = &decoded[78..82];
        let computed_checksum = sha256d(payload);
        if checksum != &computed_checksum[..4] {
            return Err(Error::Bip32Error("Invalid checksum".to_string()));
        }

        if payload[45] != 0 {
            return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
        }
        // The private key is in bytes 46..78 (last 32 bytes of the payload)
        let key_bytes: [u8; 32] = decoded[46..78]
            .try_into()
            .map_err(|_| Error::Bip32Error("Failed to extract 32-byte private key".to_string()))?;

        Ok(key_bytes)
    }

}

#[derive(Debug)]
pub struct Bip32Key {
    private_key: Option<SecretKey>,
    public_key: PublicKey,
    network: Network,
    version: [u8;4],
    chain_code: [u8; 32],
    parent_fingerprint: [u8; 4],
    depth: u8,
    index: [u8; 4],
}

impl Bip32Key {
    pub fn get_private_key(&self) -> Option<Vec<u8>> {
        self.private_key.as_ref().map(|pk| pk[..].to_vec())
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }

    pub fn get_network(&self) -> Network {
        self.network
    }

    pub fn get_version(&self) -> [u8; 4] {
        self.version
    }

    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    pub fn get_parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    pub fn get_depth(&self) -> u8 {
        self.depth
    }

    pub fn get_index(&self) -> [u8; 4] {
        self.index
    }
}

// Computes the fingerprint from a public key
fn compute_fingerprint(pubkey_bytes: &[u8]) -> [u8; 4] {
    let hash = Sha256::digest(pubkey_bytes);
    let ripemd = Ripemd160::digest(&hash);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&ripemd[0..4]);
    fingerprint
}

fn base58_check_encode(data: &[u8]) -> Result<String, Error> {
    // Example validation: xprv and xpub are typically 78 bytes before checksum
    if data.len() != 78 {
        return Err(Error::Bip32Error(format!("Invalid data length for base58check encoding: {}", data.len())));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(data);
    
    // Calculate checksum
    let hash1 = sha2::Sha256::digest(data);
    let hash2 = sha2::Sha256::digest(&hash1);
    payload.extend_from_slice(&hash2[..4]);

    Ok(payload.to_base58())
}

// Validates and decodes a Base58Check-encoded extended key
fn decode_extended_key(input: &str) -> Result<(Vec<u8>, [u8; 4]), Error> {
    let data = input
        .from_base58()
        .map_err(|e| Error::Bip32Error(format!("Invalid base58: {:?}", e)))?;
    if data.len() != 82 {
        return Err(Error::Bip32Error("Invalid extended key length".to_string()));
    }
    let payload = &data[..78];
    let checksum = &data[78..82];
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    if checksum != &hash2[..4] {
        return Err(Error::Bip32Error("Invalid checksum".to_string()));
    }
    let mut version = [0u8; 4];
    version.copy_from_slice(&data[0..4]);
    Ok((payload.to_vec(), version))
}

// Helper function for derive_seed_or_extended_key() that derives a child key from the current key
fn derive_child_key(
    private_key: &mut Option<SecretKey>,
    public_key: &mut Option<PublicKey>,
    chain_code: &mut [u8; 32],
    parent_fingerprint: &mut [u8; 4],
    depth: &mut u8,
    index: u32,
    hardened: bool,
) -> Result<(), Error> {
    let secp = Secp256k1::new();
    if hardened && private_key.is_none() {
        return Err(Error::Bip32Error("Cannot derive hardened keys from public key".to_string()));
    }
    *depth = depth.checked_add(1).ok_or_else(|| Error::Bip32Error("Depth overflow".to_string()))?;

    let mut data = [0u8; 37];
    let pubkey = public_key.unwrap_or_else(|| PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    let pubkey_bytes = pubkey.serialize();
    if hardened {
        data[0] = 0;
        data[1..33].copy_from_slice(&private_key.as_ref().unwrap()[..]);
    } else {
        data[0..33].copy_from_slice(&pubkey_bytes);
    }
    data[33..37].copy_from_slice(&index.to_be_bytes());

    let key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, chain_code);
    let i = ring_hmac::sign(&key, &data).as_ref().to_vec();
    let (il, ir) = i.split_at(32);

    if private_key.is_some() {
        let tweak = SecretKey::from_byte_array(il.try_into().map_err(|_| Error::Bip32Error("Invalid child private key length".to_string()))?)
            .map_err(|e| Error::Bip32Error(format!("Invalid child private key: {}", e)))?;
        let new_private_key = private_key.unwrap()
            .add_tweak(&tweak.into())
            .map_err(|_| Error::Bip32Error("Private key tweak overflow".to_string()))?;
        *private_key = Some(new_private_key);
        *public_key = Some(PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    } else {
        let tweak = SecretKey::from_byte_array(il.try_into().map_err(|_| Error::Bip32Error("Invalid tweak length".to_string()))?)
            .map_err(|e| Error::Bip32Error(format!("Invalid tweak: {}", e)))?;
        *public_key = Some(public_key.unwrap()
            .add_exp_tweak(&secp, &tweak.into())
            .map_err(|_| Error::Bip32Error("Public key tweak overflow".to_string()))?);
    }

    chain_code.copy_from_slice(ir);
    *parent_fingerprint = compute_fingerprint(&pubkey_bytes);

    Ok(())
}

// Powerful function that handles bascially everything you need
pub fn derive_seed_or_extended_key(
    input: &str,
    path: &str,
    network: Network,
) -> Result<ExtendedKeypair, Error> {
    // INIT
    let secp = Secp256k1::new();
    let mut depth: u8 = 0;
    let mut parent_index: [u8; 4] = [0; 4];
    let mut child_number: [u8; 4] = [0; 4];
    let mut private_key: Option<SecretKey> = None;
    let mut public_key: Option<PublicKey> = None;
    let mut chain_code: [u8; 32] = [0; 32]; // Initialize chain_code to zeros
    let mut parent_fingerprint: [u8; 4] = [0; 4];

    // Normalize path: convert "m" or Empty String into to "m/" else add / at the end if not
    let normalized_path_2 = if path.is_empty() {
        format!("m/")
    } else if !path.ends_with('/') {
        format!("{}/", path)
    } else {
        path.to_string()
    };

    // Convert path starting with "path" to start with "m"
    let normalized_path = if normalized_path_2.starts_with("path") {
        format!("m{}", &normalized_path_2[4..])
    } else {
        normalized_path_2.clone()
    };

    // Validate path
    if !normalized_path.is_empty() && !normalized_path.starts_with("m"){
        return Err(Error::Bip32Error("Path must start with 'm'".to_string()));
    }
    let re = regex::Regex::new(r"^m(/(\d+[']?))*/?$").map_err(|e| Error::Bip32Error(format!("Regex error: {}", e)))?;
    if !normalized_path.is_empty() && !re.is_match(&normalized_path) {
        return Err(Error::Bip32Error("Invalid derivation path format".to_string()));
    }

    // Determine if input is a seed (hex) or extended key (xprv/xpub/tprv/tpub)

    let is_extended_key = input.starts_with("xprv") || input.starts_with("xpub") || input.starts_with("tprv") || input.starts_with("tpub");
    if is_extended_key {
    // Decode and validate extended key
    let (data, version) = decode_extended_key(input)?;
    depth = data[4];
    parent_fingerprint.copy_from_slice(&data[5..9]);
    parent_index.copy_from_slice(&data[9..13]);
    chain_code.copy_from_slice(&data[13..45]);

    // Check if it's a private or public key
    let is_private = version == ExtendedKeypair::set_version_bytes(network, true);
    if is_private {
        // Private key: data[45] is 0x00, followed by 32-byte private key
        if data[45] != 0 {
            return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
        }       
        private_key = Some(SecretKey::from_byte_array(
            data[46..78]
                .try_into()
                .map_err(|e| Error::Bip32Error(format!("Invalid private key length: {}", e)))?,
        )
        .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?);
        public_key = Some(PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    } else {
        public_key = Some(PublicKey::from_byte_array_compressed(
            data[45..78]
                .try_into()
                .map_err(|e| Error::Bip32Error(format!("Invalid public key length: {}", e)))?,
        )
        .map_err(|e| Error::Bip32Error(format!("Invalid public key: {}", e)))?);
    }
    // Return input key if path is "m" or empty
    if normalized_path == "m/" || normalized_path == "path/" || normalized_path.is_empty() {
        let extended_public_key = if !is_private {
            input.to_string()
        } else {
            let mut xpub_data = Vec::new();
            xpub_data.extend_from_slice(&ExtendedKeypair::set_version_bytes(network, false));
            xpub_data.push(depth);
            xpub_data.extend_from_slice(&parent_fingerprint);
            xpub_data.extend_from_slice(&parent_index);
            xpub_data.extend_from_slice(&chain_code);
            xpub_data.extend_from_slice(&public_key.unwrap().serialize());
            base58_check_encode(&xpub_data)?
        };
        return Ok(ExtendedKeypair {
            extended_private_key: if is_private { input.to_string() } else { String::new() },
            extended_public_key
        });
    }
} else {
    // Assume input is a hex seed
    let seed = hex::decode(input)
        .map_err(|e| Error::Bip32Error(format!("Invalid hex seed: {}", e)))?;
    // Validate seed length (BIP-32 recommends 128-512 bits, i.e., 16-64 bytes)
    if seed.len() < 16 || seed.len() > 64 {
        println!("{:?}", &seed);
        return Err(Error::Bip32Error("Invalid seed length".to_string()));
    } 

    // Derive master key using HMAC-SHA512 with key "Bitcoin seed"
    let key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, b"Bitcoin seed");
    let i = ring_hmac::sign(&key, &seed).as_ref().to_vec();

    // Split into IL (private key) and IR (chain code)
    let (il, ir) = i.split_at(32);

    private_key = Some(SecretKey::from_byte_array(
        il.try_into()
            .map_err(|e| Error::Bip32Error(format!("Invalid private key length: {}", e)))?,
    )
    .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?);
    chain_code.copy_from_slice(ir);
    parent_fingerprint = [0; 4]; // Master key has no parent
}

// Process derivation path
let path_parts: Vec<&str> = normalized_path.trim_start_matches("m/").trim_end_matches('/').split('/').filter(|s| !s.is_empty()).collect();
for part in path_parts {
    if part.is_empty() {
        return Err(Error::Bip32Error("Empty path segment".to_string()));
    }
    let hardened = part.ends_with("'");
    let index_str = part.trim_end_matches("'");
    if index_str.is_empty() || index_str.chars().any(|c| !c.is_digit(10)) {
        return Err(Error::Bip32Error(format!("Invalid path index: {}", part)));
    }
    let index: u32 = index_str.parse().map_err(|_| Error::Bip32Error(format!("Invalid path index: {}", part)))?;
    if index > 0x7FFFFFFF && !hardened {
        return Err(Error::Bip32Error(format!("Non-hardened index {} exceeds maximum (2^31-1)", index)));
    }
    child_number = index.to_be_bytes();

    derive_child_key(
        &mut private_key,
        &mut public_key,
        &mut chain_code,
        &mut parent_fingerprint,
        &mut depth,
        index,
        hardened,
    )?;
        
    }
    
    // Serialize extended public key (xpub/tpub)
    let xpub_version = ExtendedKeypair::set_version_bytes(network, false);
    let mut xpub_data = Vec::new();
    xpub_data.extend_from_slice(&xpub_version);
    xpub_data.push(depth);
    xpub_data.extend_from_slice(&parent_fingerprint);
    xpub_data.extend_from_slice(&child_number);
    xpub_data.extend_from_slice(&chain_code);
    let pubkey = public_key.unwrap_or_else(|| PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    xpub_data.extend_from_slice(&pubkey.serialize());
    let extended_public_key = base58_check_encode(&xpub_data)?;

    // Serialize extended private key (xprv) if available
    let extended_private_key = if let Some(pk) = private_key {
        let xprv_version = ExtendedKeypair::set_version_bytes(network, true);
        let mut xprv_data = Vec::new();
        xprv_data.extend_from_slice(&xprv_version);
        xprv_data.push(depth);
        xprv_data.extend_from_slice(&parent_fingerprint);
        xprv_data.extend_from_slice(&child_number);
        xprv_data.extend_from_slice(&chain_code);
        xprv_data.push(0);
        xprv_data.extend_from_slice(&pk[..]);
        base58_check_encode(&xprv_data)?
    } else {
        String::new()
    };
            
    Ok(ExtendedKeypair { extended_private_key, extended_public_key })
}
