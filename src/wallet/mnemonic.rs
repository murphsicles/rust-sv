///! Converts a mnemonic phrase to a 64-byte seed using BIP-39 PBKDF2 derivation.

use crate::util::bits::Bits;
use crate::util::{Error, Result};
use ring::digest::{digest, SHA256};
use std::str;
use std::collections::HashSet;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use rand::rngs::OsRng;
use rand::RngCore;

/// Wordlist language
#[derive(Clone, Copy)]
pub enum Wordlist {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

/// Loads the word list for a given language
pub fn load_wordlist(wordlist: Wordlist) -> Vec<String> {
    match wordlist {
        Wordlist::ChineseSimplified => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_simplified.txt"))
        }
        Wordlist::ChineseTraditional => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_traditional.txt"))
        }
        Wordlist::English => load_wordlist_internal(include_bytes!("wordlists/english.txt")),
        Wordlist::French => load_wordlist_internal(include_bytes!("wordlists/french.txt")),
        Wordlist::Italian => load_wordlist_internal(include_bytes!("wordlists/italian.txt")),
        Wordlist::Japanese => load_wordlist_internal(include_bytes!("wordlists/japanese.txt")),
        Wordlist::Korean => load_wordlist_internal(include_bytes!("wordlists/korean.txt")),
        Wordlist::Spanish => load_wordlist_internal(include_bytes!("wordlists/spanish.txt")),
    }
}

fn load_wordlist_internal(bytes: &[u8]) -> Vec<String> {
    let text: String = str::from_utf8(bytes).unwrap().to_string();
    text.lines().map(|s| s.to_string()).collect()
}

pub fn generate_new_seed(word_count: usize, wordlist: Wordlist) -> Result<(String, String, String)> {
    // Validate word_count (must be 12, 15, 18, 21, or 24)
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(Error::BadArgument(format!(
            "Invalid word count: must be 12, 15, 18, 21, or 24, got {}",
            word_count
        )));
    }

    // Calculate entropy size in bytes (word_count * 11 / 33 * 32)
    let entropy_bits = word_count * 11 - word_count / 3;
    let entropy_bytes = entropy_bits / 8;

    // Generate random entropy
    let mut entropy = vec![0u8; entropy_bytes];
    OsRng.fill_bytes(&mut entropy);

    // Load the specified wordlist
    let wordlist = load_wordlist(wordlist);

    // Encode entropy to mnemonic words
    let mnemonic_words = mnemonic_encode(&entropy, &wordlist);
    let mnemonic = mnemonic_words.join(" ");

    // Validate the number of mnemonic words
    if mnemonic_words.len() != word_count {
        return Err(Error::BadArgument(format!(
            "Generated mnemonic has {} words, expected {}",
            mnemonic_words.len(),
            word_count
        )));
    }

    // Convert entropy to hex string
    let entropy_hex = hex::encode(&entropy);

    // Derive seed from mnemonic (using empty passphrase)
    let seed = mnemonic_to_seed(&mnemonic, "")?;
    let seed_hex = hex::encode(&seed);

    Ok((mnemonic, entropy_hex, seed_hex))
}

/// Encodes data into a mnemonic using BIP-39
pub fn mnemonic_encode(data: &[u8], word_list: &[String]) -> Vec<String> {
    let hash = digest(&SHA256, &data);
    let mut words = Vec::with_capacity((data.len() * 8 + data.len() / 32 + 10) / 11);
    let mut bits = Bits::from_slice(data, data.len() * 8);
    bits.append(&Bits::from_slice(hash.as_ref(), data.len() / 4));
    for i in 0..bits.len / 11 {
        words.push(word_list[bits.extract(i * 11, 11) as usize].clone());
    }
    let rem = bits.len % 11;
    if rem != 0 {
        let n = bits.extract(bits.len / 11 * 11, rem) << (8 - rem);
        words.push(word_list[n as usize].clone());
    }
    words
}

/// Decodes a mnemonic into data using BIP-39
pub fn mnemonic_decode(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>> {
    let mut bits = Bits::with_capacity(mnemonic.len() * 11);
    for word in mnemonic {
        let value = match word_list.binary_search(word) {
            Ok(value) => value,
            Err(_) => return Err(Error::BadArgument(format!("Bad word: {}", word))),
        };
        let word_bits = Bits::from_slice(&[(value >> 3) as u8, ((value & 7) as u8) << 5], 11);
        bits.append(&word_bits);
    }
    let data_len = bits.len * 32 / 33;
    let cs_len = bits.len / 33;
    let cs = digest(&SHA256, &bits.data[0..data_len / 8]);
    let cs_bits = Bits::from_slice(cs.as_ref(), cs_len);
    if cs_bits.extract(0, cs_len) != bits.extract(data_len, cs_len) {
        return Err(Error::BadArgument("Invalid checksum".to_string()));
    }
    Ok(bits.data[0..data_len / 8].to_vec())
}

// Function to autoload the wordlist based on mnemonic words
pub fn autoload_wordlist(mnemonic: &str) -> Result<Vec<String>> {
    // Split the mnemonic into words
    let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
    
    // List of supported wordlist languages
    let languages = [
        Wordlist::English,
        Wordlist::ChineseSimplified,
        Wordlist::ChineseTraditional,
        Wordlist::French,
        Wordlist::Italian,
        Wordlist::Japanese,
        Wordlist::Korean,
        Wordlist::Spanish,
    ];
    
    let mut matching_wordlist = None;
    
    // Check each wordlist
    for language in &languages {
        let wordlist = load_wordlist(*language);
        let wordlist_set: HashSet<&String> = wordlist.iter().collect();
        
        // Check if all mnemonic words are in this wordlist
        let all_words_valid = words.iter().all(|word| wordlist_set.contains(word));
        
        if all_words_valid {
            if matching_wordlist.is_some() {
                // If another wordlist already matched, the mnemonic is ambiguous
                return Err(Error::BadArgument("Mnemonic matches multiple wordlists".to_string()));
            }
            matching_wordlist = Some(wordlist);
        }
    }
    
    match matching_wordlist {
        Some(wordlist) => Ok(wordlist),
        None => Err(Error::BadArgument("No matching wordlist found for the mnemonic".to_string())),
    }
}

pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    // Normalize mnemonic: lowercase, trim, and replace multiple spaces with single
    let normalized = mnemonic
        .to_lowercase()
        .trim()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Validate mnemonic: must have 12, 15, 18, 21, or 24 words
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(Error::BadArgument(format!("Invalid mnemonic: must have 12, 15, 18, 21, or 24 words, got {}", words.len())));
    }

    // Validate mnemonic words against wordlist
    let wordlist = autoload_wordlist(&normalized)?;
    let mnemonic_vec: Vec<String> = words.iter().map(|s| s.to_string()).collect();
    let _entropy = mnemonic_decode(&mnemonic_vec, &wordlist).map_err(|e| Error::BadArgument(format!("Invalid mnemonic: {}", e)))?;

    // Convert mnemonic to bytes
    let mnemonic_bytes = normalized.as_bytes();

    // Create BIP-39 salt: "mnemonic" + passphrase
    let salt = format!("mnemonic{}", passphrase);
    let salt_bytes = salt.as_bytes();

    // PBKDF2 parameters
    const ITERATIONS: u32 = 2048;
    const KEY_LENGTH: usize = 64; // 512 bits

    // Initialize output buffer for the seed
    let mut seed = [0u8; KEY_LENGTH];

    // Derive seed using PBKDF2 with SHA-512
    pbkdf2_hmac::<Sha512>(mnemonic_bytes, salt_bytes, ITERATIONS, &mut seed);

    Ok(seed)
}