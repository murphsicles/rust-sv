/////////////////////////////////////////////////////////////////////////////////////////
////////////////////////// PUBLIC SERVICE ANNOUNCEMENT //////////////////////////////////
//////////////////// - THE EXTENDED DERIVATION PATH SYNTAX - ////////////////////////////
//////////////////////////// as conceived by -NИЖKY~ ////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////// extended_derivationpath = "m/423/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]" ////
/////////////////////////////////////////////////////////////////////////////////////////
//
//  The Extended Derivationpath Syntax is an answer to the proposed one time usage 
//  of Bitcoin adresses according the the Bitcoin Whitepaper in Section 10.
//  It captures all UTXOs for the correct balance and content. 
//  This approach reduces sync time as much as possible without relying intensively on a
//  UTXO storage service. This approach is suitable for scale.
// 
//  How the string is being read:
//  Normal Derivationpath: m/423/0/0/ = path/
//  Extended Derivationpath = "m/423/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]" 
//
//  Type: path/[<typeIndex>:<index>;]
//      Type Index 0: Received Payments / Change Adresses (All your positive amounts)
//      Type Index 1: Sent Payments Adresses (All your negative amounts)
//      Type Index 2: Received Inscriptions (All your bought items)
//      Type Index 3: Sent Inscriptions (All your sold items)
//      -> Can be expanded for more types
//
//  Hardended TypeIndexes are also supported
//
//  Spots of Interest: <index>
//  We extract 0:70-105 from the Extended Derivation path and look it up.
//  Be aware of the Semicolon ; at each end of each section.
//  It marks the end of each section (path branch), so we can extract each section better.
//
//  i_min = 70  - Means below Index 70 we assume to have a balance of 0 AND everything 
//                below that index number has been used previously. Reuse is not recommended 
//                for Privacy. Index 70 marks the first UTXO with a positive balance.
//  i_max = 105 - Means we assume everything above Index 105 has a balance of 0 Satoshi as well 
//                because everything above that number is unused.
//  i_unused = i_max + 1 = 106 - Marks the first unused adresse that we can use for our type index use case.
//  We can also apply a gap_limit on i_max, so we see if we received anything.
//
//  To receive your transaction history, you have to get i_max as your latest UTXO and go backwards in time.
//  The indexes should all be in chronolocial order when one-time usage of Bitcoin addresses is applied correctly.

// use crate::wallet::adressing::{exclude_brackets, get_nonhardend_typeindex_indices};
use crate::wallet::derivation::{derive_seed_or_extended_key, ExtendedKey, Network};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use base58::{ToBase58, FromBase58};
use crate::util::{Error, Result, sha256d};

pub mod constants {
    pub const MAINNET_P2PKH_VERSION: u8 = 0x00;
    pub const MAINNET_P2SH_VERSION: u8 = 0x05;
    pub const TESTNET_P2PKH_VERSION: u8 = 0x6F;
    pub const TESTNET_P2SH_VERSION: u8 = 0xC4;
}

pub fn extract_brackets(extended_derivationpath: &str) -> Option<String> {
    // Find the start and end of the bracketed content
    let start = extended_derivationpath.find('[')?;
    let end = extended_derivationpath.rfind(']')?;
    
    // Extract the content between brackets (excluding the brackets)
    Some(extended_derivationpath[start + 1..end].to_string())
}

pub fn exclude_brackets(extended_derivationpath: &str) -> String {
    // Find the start of the bracketed content
    if let Some(start) = extended_derivationpath.find('[') {
        // Return the substring before the opening bracket, removing any trailing slash
        extended_derivationpath[..start].trim_end_matches('/').to_string()
    } else {
        // If no brackets, return the input string, removing any trailing slash
        extended_derivationpath.trim_end_matches('/').to_string()
    }
}

pub fn extract_typeindex(bracket_content: &str, typeindex: &str) -> Option<String> {
    // Split the input by semicolons to get individual entries
    let entries: Vec<&str> = bracket_content.trim_end_matches(';').split(';').collect();

    // Iterate through entries to find the one matching typeindex
    for entry in entries {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() == 2 {
            let index_str = parts[0].trim();
            // Check if typeindex is a non-hardened index (can be parsed as usize)
            let cleaned_typeindex = typeindex.trim_end_matches(|c| c == 'H' || c == 'h' || c == '\'');
            if let Ok(index) = cleaned_typeindex.parse::<usize>() {
                // Handle non-hardened indices: strip H, h, or ' from entry's index
                let cleaned_index = index_str.trim_end_matches(|c| c == 'H' || c == 'h' || c == '\'');
                if let Ok(entry_index) = cleaned_index.parse::<usize>() {
                    if entry_index == index {
                        return Some(parts[1].to_string());
                    }
                }
            } else {
                // Handle hardened indices: direct comparison
                if index_str == typeindex {
                    return Some(parts[1].to_string());
                }
            }
        }
    }

    None
}

pub fn get_indexes_in_array(typeindex_content: &str) -> Result<Vec<usize>> {
    let mut indices = Vec::new();

    // Split input by commas to handle combined ranges and single numbers
    for part in typeindex_content.split(',').filter(|s| !s.is_empty()) {
        if part.contains('-') {
            // Handle range (e.g., "70-105" or "10-15")
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::BadData("Invalid range format".to_string()));
            }
            let start = range_parts[0]
                .parse::<usize>()
                .map_err(Error::ParseIntError)?;
            let end = range_parts[1]
                .parse::<usize>()
                .map_err(Error::ParseIntError)?;
            if start > end {
                return Err(Error::BadData("Start of range cannot be greater than end".to_string()));
            }
            indices.extend(start..=end);
        } else {
            // Handle single number (e.g., "88" or "69")
            let number = part
                .parse::<usize>()
                .map_err(Error::ParseIntError)?;
            indices.push(number);
        }
    }

    // Remove duplicates and sort
    indices.sort_unstable();
    indices.dedup();

    Ok(indices)
}

pub fn get_typeindex_indices(extended_derivationpath: &str, typeindex: &str) -> Result<Vec<usize>> {
    let bracket_content = extract_brackets(extended_derivationpath)
        .ok_or_else(|| Error::BadData("Failed to extract brackets".to_string()))?;
    let typeindex_content = extract_typeindex(&bracket_content, typeindex)
        .ok_or_else(|| Error::BadData(format!("Failed to extract typeindex {}", typeindex)))?;
    get_indexes_in_array(&typeindex_content)
}

/////////////// 

pub fn encode_address(_network: Network, version: u8, payload: &[u8]) -> Result<String> {
    if payload.len() != 20 {
        return Err(Error::BadArgument("Payload must be 20 bytes".to_string()));
    }
    let mut v = Vec::with_capacity(25);
    v.push(version);
    v.extend_from_slice(payload);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum.0[..4]);
    Ok(v.to_base58())
}

pub fn decode_address(input: &str) -> Result<(u8, Vec<u8>)> {
    let bytes = input.from_base58().map_err(|e| Error::FromBase58Error(e))?;
    if bytes.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }
    let checksum = sha256d(&bytes[..21]);
    if checksum.0[..4] != bytes[21..] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }
    let version = bytes[0];
    let payload = bytes[1..21].to_vec();
    Ok((version, payload))
}

pub fn encode_p2pkh_address(network: Network, pubkey_hash: &[u8]) -> Result<String> {
    let version = match network {
        Network::Mainnet => constants::MAINNET_P2PKH_VERSION,
        Network::Testnet | Network::STN => constants::TESTNET_P2PKH_VERSION,
    };
    encode_address(network, version, pubkey_hash)
}

pub fn encode_p2sh_address(network: Network, script_hash: &[u8]) -> Result<String> {
    let version = match network {
        Network::Mainnet => constants::MAINNET_P2SH_VERSION,
        Network::Testnet | Network::STN => constants::TESTNET_P2SH_VERSION,
    };
    encode_address(network, version, script_hash)
}

pub fn validate_address(network: Network, address: &str) -> Result<()> {
    let (version, _) = decode_address(address)?;
    let expected_version = match network {
        Network::Mainnet => [constants::MAINNET_P2PKH_VERSION, constants::MAINNET_P2SH_VERSION],
        Network::Testnet | Network::STN => [constants::TESTNET_P2PKH_VERSION, constants::TESTNET_P2SH_VERSION],
    };
    if !expected_version.contains(&version) {
        return Err(Error::BadData("Invalid address version for network".to_string()));
    }
    Ok(())
}

pub fn get_publickey_array_from_extended_derivationpath(
    extended_key: &str,
    extended_derivationpath: &str,
    typeindex: &str,
    network: Network,
) -> Result<Vec<String>> {

    // Get the indices for the given typeindex
    let indices = get_typeindex_indices(extended_derivationpath, typeindex)?;

    // Extract the base path (e.g., m/69'/0'/0')
    let base_path = exclude_brackets(extended_derivationpath);

    println!("Works with: {:?} and {:?} and {:?}", base_path, typeindex,  indices);

    // Derive addresses for each index
    let addresses: Result<Vec<String>> = indices.into_iter().map(|index| {
        // Construct the full derivation path for the child (e.g., m/69'/0'/0'/index)
        let child_path = format!("{}/{}/{}", base_path, typeindex, index);
        
        // Derive the child key using derive_seed_or_extended_key
        let child_keypair = derive_seed_or_extended_key(extended_key, &child_path, network)?;
        
        // Extract the public key from the extended public key
        let extended_key_obj = ExtendedKey::decode(&child_keypair.extended_public_key)?;
        let bip32_key = extended_key_obj.to_bip32_keyobject()?;
        let public_key_bytes = bip32_key.get_public_key();
        
        // Get Public Key
        // Convert public key bytes to Hex-encoded public key
        let address = hex::encode(public_key_bytes);
        Ok(address)
    }).collect();

    addresses
}

// Custom function to generate P2PKH address from a public key using encode_p2pkh_address
pub fn public_key_to_p2pkh_address(pubkey: &[u8], network: Network) -> Result<String> {
    // Step 1: SHA-256 hash of the public key
    let sha256_hash = Sha256::digest(pubkey);
    
    // Step 2: RIPEMD-160 hash of the SHA-256 result
    let pubkey_hash = Ripemd160::digest(&sha256_hash);
    
    // Step 3: Use encode_p2pkh_address to handle version byte, checksum, and Base58Check encoding
    encode_p2pkh_address(network, &pubkey_hash)
}

pub fn get_adresse_array_from_extended_derivationpath(
    extended_key: &str,
    extended_derivationpath: &str,
    typeindex: &str,
    network: Network,
) -> Result<Vec<String>> {


    // Get the indices for the given typeindex
    let indices = get_typeindex_indices(extended_derivationpath, typeindex)?;

    // Extract the base path (e.g., m/69'/0'/0')
    let base_path = exclude_brackets(extended_derivationpath);

    println!("Works with: {:?} and {:?} and {:?}", base_path, typeindex,  indices);

    // Derive addresses for each index
    let addresses: Result<Vec<String>> = indices.into_iter().map(|index| {
        // Construct the full derivation path for the child (e.g., m/69'/0'/0'/index)
        let child_path = format!("{}/{}/{}", base_path, typeindex, index);
        
        // Derive the child key using derive_seed_or_extended_key
        let child_keypair = derive_seed_or_extended_key(extended_key, &child_path, network)?;
        
        // Extract the public key from the extended public key
        let extended_key_obj = ExtendedKey::decode(&child_keypair.extended_public_key)?;
        let bip32_key = extended_key_obj.to_bip32_keyobject()?;
        let public_key_bytes = bip32_key.get_public_key();
        
        // Generate P2PKH address
        let address = public_key_to_p2pkh_address(&public_key_bytes, network)?;
        Ok(address)
    }).collect();

    addresses
}

pub fn get_unused_address(
    extended_key: &str,
    extended_derivation_path: &str,
    type_index: &str,
    network: Network,
    gap_limit: usize,
    pk_or_bitcoin_address: bool,
) -> Result<String> {
    let type_index_indices = get_typeindex_indices(extended_derivation_path, type_index)?;

    // Array adjustment while looking for balance, then:
    let _i_min = type_index_indices
        .iter()
        .min()
        .ok_or_else(|| Error::BadData("No indices found".to_string()))?;
    let i_max = type_index_indices
        .iter()
        .max()
        .ok_or_else(|| Error::BadData("No indices found".to_string()))?;
    let i_unused = i_max + 1;
    let _i_gap_max = i_max + gap_limit;

    // Construct the unused path based on derivation path type
    let unused_path = if extended_derivation_path.starts_with("path/") {
        // For path/ style, use type_index and i_unused directly
        format!("path/{}/{}", type_index, i_unused)
    } else if extended_derivation_path.starts_with("m/") {
        // For m/ style, use base path without brackets
        let base_path = exclude_brackets(extended_derivation_path);
        println!("DEBUG - base_path {}", base_path);
        format!("{}/{}/{}", base_path, type_index, i_unused)
    } else {
        return Err(Error::BadData(
            "Invalid derivation path: must start with 'm/' or 'path/'".to_string(),
        ));    
    };

    println!("DEBUG - unused_path {}", unused_path);

    // Derive the child keypair for the unused path
    let child_keypair = derive_seed_or_extended_key(extended_key, &unused_path, network)?;

    // Extract the public key from the extended public key
    let extended_key_obj = ExtendedKey::decode(&child_keypair.extended_public_key)
        .map_err(|e| Error::Bip32Error(format!("Failed to decode extended public key: {}", e)))?;
    let bip32_key = extended_key_obj
        .to_bip32_keyobject()
        .map_err(|e| Error::Bip32Error(format!("Failed to convert to BIP-32 key object: {}", e)))?;
    let public_key_bytes = bip32_key.get_public_key();

    // Return either the hex-encoded public key or the P2PKH address
    if pk_or_bitcoin_address {
        // Return hex-encoded public key
        Ok(hex::encode(public_key_bytes))
    } else {
        // Generate P2PKH address from the public key
        let address = public_key_to_p2pkh_address(&public_key_bytes, network)?;
        Ok(address)
    }
}