//! Transaction sighash helpers

use crate::messages::{OutPoint, TxIn, TxOut};
use crate::script::{op_codes, Script};
use crate::util::{var_int, Error, Hash256, Result, sha256d};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use secp256k1::{Message, Secp256k1, SecretKey};
use secp256k1::ecdsa::Signature;
use smallvec::SmallVec;
use std::io::{Cursor, Read, Write};

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_FORKID: u8 = 0x40;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// The 24-bit fork ID for Bitcoin Cash / SV
const FORK_ID: u32 = 0;

/// Maximum number of inputs/outputs for sighash to prevent DoS
const MAX_IO: usize = 1_000_000;

/// Generates a transaction digest for signing
///
/// This will use either BIP-143 or the legacy algorithm depending on if SIGHASH_FORKID is set.
///
/// # Arguments
///
/// * `tx` - Spending transaction
 * `n_input` - Spending input index
 * `script_code` - The lock_script of the output being spent. This may be a subset of the
lock_script if OP_CODESEPARATOR is used.
 * `satoshis` - The satoshi amount in the output being spent
 * `sighash_type` - Sighash flags
 * `cache` - Cache to store intermediate values for future sighash calls.
pub fn sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if tx.inputs.len() > MAX_IO || tx.outputs.len() > MAX_IO {
        return Err(Error::BadData("Too many inputs/outputs".to_string()));
    }
    if sighash_type & SIGHASH_FORKID != 0 {
        bip143_sighash(tx, n_input, script_code, satoshis, sighash_type, cache)
    } else {
        legacy_sighash(tx, n_input, script_code, sighash_type)
    }
}

/// Cache for sighash intermediate values to avoid quadratic hashing
///
/// This is only valid for one transaction, but may be used for multiple signatures.
pub struct SigHashCache {
    hash_prevouts: Option<Hash256>,
    hash_sequence: Option<Hash256>,
    hash_outputs: Option<Hash256>,
}

impl SigHashCache {
    /// Creates a new cache
    pub fn new() -> SigHashCache {
        SigHashCache {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
}

/// Generates a transaction digest for signing using BIP-143
///
/// This is to be used for all transactions after the August 2017 fork.
/// It fixes quadratic hashing and includes the satoshis spent in the hash.
fn bip143_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    satoshis: i64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("input out of tx_in range".to_string()));
    }

    let mut s = SmallVec::<[u8; 1024]>::new();
    let base_type = sighash_type & 31;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;

    // 1. Serialize version
    s.extend_from_slice(&tx.version.to_le_bytes());

    // 2. Serialize hash of prevouts
    if !anyone_can_pay {
        if cache.hash_prevouts.is_none() {
            let mut prev_outputs = SmallVec::<[u8; 1024]>::new();
            for input in tx.inputs.iter() {
                input.prev_output.write(&mut prev_outputs)?;
            }
            cache.hash_prevouts = Some(sha256d(&prev_outputs));
        }
        s.extend_from_slice(&cache.hash_prevouts.unwrap().0);
    } else {
        s.extend_from_slice(&[0; 32]);
    }

    // 3. Serialize hash of sequences
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_sequence.is_none() {
            let mut sequences = SmallVec::<[u8; 1024]>::new();
            for tx_in in tx.inputs.iter() {
                sequences.extend_from_slice(&tx_in.sequence.to_le_bytes());
            }
            cache.hash_sequence = Some(sha256d(&sequences));
        }
        s.extend_from_slice(&cache.hash_sequence.unwrap().0);
    } else {
        s.extend_from_slice(&[0; 32]);
    }

    // 4. Serialize prev output
    tx.inputs[n_input].prev_output.write(&mut s)?;

    // 5. Serialize input script
    var_int::write(script_code.len() as u64, &mut s)?;
    s.extend_from_slice(script_code);

    // 6. Serialize satoshis
    s.extend_from_slice(&satoshis.to_le_bytes());

    // 7. Serialize sequence
    s.extend_from_slice(&tx.inputs[n_input].sequence.to_le_bytes());

    // 8. Serialize hash of outputs
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        if cache.hash_outputs.is_none() {
            let mut size = 0;
            for tx_out in tx.outputs.iter() {
                size += tx_out.size();
            }
            let mut outputs = SmallVec::<[u8; 1024]>::new();
            for tx_out in tx.outputs.iter() {
                tx_out.write(&mut outputs)?;
            }
            cache.hash_outputs = Some(sha256d(&outputs));
        }
        s.extend_from_slice(&cache.hash_outputs.unwrap().0);
    } else if base_type == SIGHASH_SINGLE && n_input < tx.outputs.len() {
        let mut outputs = SmallVec::<[u8; 1024]>::new();
        tx.outputs[n_input].write(&mut outputs)?;
        s.extend_from_slice(&sha256d(&outputs).0);
    } else {
        s.extend_from_slice(&[0; 32]);
    }

    // 9. Serialize lock_time
    s.extend_from_slice(&tx.lock_time.to_le_bytes());

    // 10. Serialize hash type
    let sighash = (FORK_ID << 8) | sighash_type as u32;
    s.extend_from_slice(&sighash.to_le_bytes());

    Ok(sha256d(&s))
}

/// Generates the transaction digest for signing using the legacy algorithm
///
/// This is used for all transaction validation before the August 2017 fork.
fn legacy_sighash(
    tx: &Tx,
    n_input: usize,
    script_code: &[u8],
    sighash_type: u8,
) -> Result<Hash256> {
    if n_input >= tx.inputs.len() {
        return Err(Error::BadArgument("input out of tx_in range".to_string()));
    }

    let mut s = SmallVec::<[u8; 1024]>::new();
    let base_type = sighash_type & 31;
    let anyone_can_pay = sighash_type & SIGHASH_ANYONECANPAY != 0;

    // Remove all instances of OP_CODESEPARATOR from the script_code
    let mut sub_script = Vec::new();
    let mut i = 0;
    while i < script_code.len() {
        let next = next_op(i, script_code);
        if script_code[i] != op_codes::OP_CODESEPARATOR {
            sub_script.extend_from_slice(&script_code[i..next]);
        }
        i = next;
    }

    // Serialize the version
    s.extend_from_slice(&tx.version.to_le_bytes());

    // Serialize the inputs
    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    var_int::write(n_inputs as u64, &mut s)?;
    for i in 0..tx.inputs.len() {
        let i = if anyone_can_pay { n_input } else { i };
        let mut tx_in = tx.inputs[i].clone();
        if i == n_input {
            tx_in.unlock_script = Script(Vec::with_capacity(4 + sub_script.len()));
            tx_in.unlock_script.0.extend_from_slice(&sub_script);
        } else {
            tx_in.unlock_script = Script(vec![]);
            if base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE {
                tx_in.sequence = 0;
            }
        }
        tx_in.write(&mut s)?;
        if anyone_can_pay {
            break;
        }
    }

    // Serialize the outputs
    let tx_out_list = if base_type == SIGHASH_NONE {
        vec![]
    } else if base_type == SIGHASH_SINGLE {
        if n_input >= tx.outputs.len() {
            return Err(Error::BadArgument("input out of tx_out range".to_string()));
        }
        let mut truncated_out = tx.outputs.clone();
        truncated_out.truncate(n_input + 1);
        truncated_out
    } else {
        tx.outputs.clone()
    };
    var_int::write(tx_out_list.len() as u64, &mut s)?;
    for i in 0..tx_out_list.len() {
        if i == n_input && base_type == SIGHASH_SINGLE {
            let empty = TxOut {
                satoshis: -1,
                lock_script: Script(vec![]),
            };
            empty.write(&mut s)?;
        } else {
            tx_out_list[i].write(&mut s)?;
        }
    }

    // Serialize the lock time
    s.extend_from_slice(&tx.lock_time.to_le_bytes());

    // Append the sighash_type and finally double hash the result
    s.extend_from_slice(&sighash_type.to_le_bytes());
    Ok(sha256d(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{OutPoint, TxIn, TxOut};
    use crate::script::{op_codes, Script};
    use crate::util::hash160::hash160;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn sighash_none() {
        let private_key = [1; 32];
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &secret_key);
        let pkh = hash160(&pk.serialize());

        let mut lock_script = Script::new();
        lock_script.append(op_codes::OP_DUP);
        lock_script.append(op_codes::OP_HASH160);
        lock_script.append_data(&pkh.0);
        lock_script.append(op_codes::OP_EQUALVERIFY);
        lock_script.append(op_codes::OP_CHECKSIG);

        let tx1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script: lock_script.clone(),
            }],
            lock_time: 0,
        };

        let tx2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            lock_time: 0,
        };

        let mut cache = SigHashCache::new();
        let hash_none = sighash(
            &tx2,
            0,
            &lock_script.0,
            10,
            SIGHASH_NONE | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_none.encode(),
            "5a4d46f5aabb2a3d3fd16ac22f1f2fb4d3ab9c7f18195e9e37e27c08f5d6a5c6"
        );
    }

    // ... (all other tests remain the same: sighash_single, sighash_none_anyone, sighash_single_anyone, sighash_all, sighash_all_anyone)
}
