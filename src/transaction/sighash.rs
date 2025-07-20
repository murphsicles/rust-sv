//! Transaction sighash helpers

use crate::messages::Tx;
use crate::util::hash256::Hash256;
use crate::util::{Error, Result};
use secp256k1::{Message, Secp256k1, SecretKey};
use secp256k1::ecdsa::Signature;
use smallvec::SmallVec;

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_FORKID: u8 = 0x40;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Maximum number of inputs/outputs for sighash to prevent DoS
const MAX_IO: usize = 1_000_000;

/// Cache of sighash digests
#[derive(Clone, Debug)]
pub struct SigHashCache {
    all_hash: Option<Hash256>,
    none_hash: Option<Hash256>,
    single_hashes: Vec<Option<Hash256>>,
    anyone_can_pay_all_hash: Option<Hash256>,
    anyone_can_pay_none_hash: Option<Hash256>,
    anyone_can_pay_single_hashes: Vec<Option<Hash256>>,
}

impl SigHashCache {
    pub fn new() -> SigHashCache {
        SigHashCache {
            all_hash: None,
            none_hash: None,
            single_hashes: vec![],
            anyone_can_pay_all_hash: None,
            anyone_can_pay_none_hash: None,
            anyone_can_pay_single_hashes: vec![],
        }
    }
}

/// Generates a signature for a transaction input
pub fn generate_signature(
    private_key: &[u8],
    sig_hash: &Hash256,
    sighash_type: u8,
) -> Result<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(Error::BadData("Invalid private key length".to_string()));
    }
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)?;
    let message = Message::from_digest(sig_hash.0);
    let signature = secp.sign_ecdsa(&message, &secret_key);
    let signature_bytes = signature.serialize_der().to_vec();
    let mut result = SmallVec::<[u8; 73]>::from_vec(signature_bytes);
    result.push(sighash_type);
    Ok(result.into_vec())
}

/// Generates a sighash for a transaction input
pub fn sighash(
    tx: &Tx,
    input: usize,
    script: &[u8],
    satoshis: u64,
    sighash_type: u8,
    cache: &mut SigHashCache,
) -> Result<Hash256> {
    let base = sighash_type & 0x1f;
    let anyone_can_pay = (sighash_type & SIGHASH_ANYONECANPAY) != 0;
    if base != SIGHASH_ALL && base != SIGHASH_NONE && base != SIGHASH_SINGLE {
        let msg = format!("Invalid sighash type: {}", sighash_type);
        return Err(Error::BadArgument(msg));
    }
    if input >= tx.inputs.len() {
        let msg = format!("Input index {} out of range", input);
        return Err(Error::BadArgument(msg));
    }
    if tx.inputs.len() > MAX_IO || tx.outputs.len() > MAX_IO {
        return Err(Error::BadData("Too many inputs/outputs".to_string()));
    }
    if base == SIGHASH_SINGLE && input >= tx.outputs.len() {
        let msg = format!("No output for input index {}", input);
        return Err(Error::BadArgument(msg));
    }

    if anyone_can_pay {
        if base == SIGHASH_ALL {
            if let Some(hash) = cache.anyone_can_pay_all_hash {
                return Ok(hash);
            }
        } else if base == SIGHASH_NONE {
            if let Some(hash) = cache.anyone_can_pay_none_hash {
                return Ok(hash);
            }
        } else if base == SIGHASH_SINGLE {
            while cache.anyone_can_pay_single_hashes.len() <= input {
                cache.anyone_can_pay_single_hashes.push(None);
            }
            if let Some(hash) = cache.anyone_can_pay_single_hashes[input] {
                return Ok(hash);
            }
        }
    } else {
        if base == SIGHASH_ALL {
            if let Some(hash) = cache.all_hash {
                return Ok(hash);
            }
        } else if base == SIGHASH_NONE {
            if let Some(hash) = cache.none_hash {
                return Ok(hash);
            }
        } else if base == SIGHASH_SINGLE {
            while cache.single_hashes.len() <= input {
                cache.single_hashes.push(None);
            }
            if let Some(hash) = cache.single_hashes[input] {
                return Ok(hash);
            }
        }
    }

    let mut v = SmallVec::<[u8; 1024]>::new();
    v.extend_from_slice(&tx.version.to_le_bytes());
    if anyone_can_pay {
        let one = 1u64;
        var_int::write(one, &mut v)?;
        v.extend_from_slice(&tx.inputs[input].prev_output.hash.0);
        v.extend_from_slice(&tx.inputs[input].prev_output.index.to_le_bytes());
        var_int::write(script.len() as u64, &mut v)?;
        v.extend_from_slice(script);
        v.extend_from_slice(&tx.inputs[input].sequence.to_le_bytes());
    } else {
        var_int::write(tx.inputs.len() as u64, &mut v)?;
        if base == SIGHASH_ALL {
            for i in 0..tx.inputs.len() {
                v.extend_from_slice(&tx.inputs[i].prev_output.hash.0);
                v.extend_from_slice(&tx.inputs[i].prev_output.index.to_le_bytes());
                if i == input {
                    var_int::write(script.len() as u64, &mut v)?;
                    v.extend_from_slice(script);
                    v.extend_from_slice(&tx.inputs[i].sequence.to_le_bytes());
                } else {
                    var_int::write(0, &mut v)?;
                    v.extend_from_slice(&tx.inputs[i].sequence.to_le_bytes());
                }
            }
        } else {
            for i in 0..tx.inputs.len() {
                v.extend_from_slice(&tx.inputs[i].prev_output.hash.0);
                v.extend_from_slice(&tx.inputs[i].prev_output.index.to_le_bytes());
                if i == input {
                    var_int::write(script.len() as u64, &mut v)?;
                    v.extend_from_slice(script);
                } else {
                    var_int::write(0, &mut v)?;
                }
                if base == SIGHASH_NONE {
                    v.extend_from_slice(&0u32.to_le_bytes());
                } else {
                    v.extend_from_slice(&tx.inputs[i].sequence.to_le_bytes());
                }
            }
        }
    }

    if base == SIGHASH_ALL {
        var_int::write(tx.outputs.len() as u64, &mut v)?;
        for output in tx.outputs.iter() {
            v.extend_from_slice(&output.satoshis.to_le_bytes());
            var_int::write(output.lock_script.0.len() as u64, &mut v)?;
            v.extend_from_slice(&output.lock_script.0);
        }
    } else if base == SIGHASH_NONE {
        var_int::write(0, &mut v)?;
    } else if base == SIGHASH_SINGLE {
        var_int::write(1, &mut v)?;
        v.extend_from_slice(&tx.outputs[input].satoshis.to_le_bytes());
        var_int::write(tx.outputs[input].lock_script.0.len() as u64, &mut v)?;
        v.extend_from_slice(&tx.outputs[input].lock_script.0);
    }

    v.extend_from_slice(&tx.lock_time.to_le_bytes());
    v.extend_from_slice(&sighash_type.to_le_bytes());

    if sighash_type & SIGHASH_FORKID != 0 {
        v.extend_from_slice(&satoshis.to_le_bytes());
        v.extend_from_slice(&tx.version.to_le_bytes());
    }

    let hash = sha256d(&v);
    if anyone_can_pay {
        if base == SIGHASH_ALL {
            cache.anyone_can_pay_all_hash = Some(hash);
        } else if base == SIGHASH_NONE {
            cache.anyone_can_pay_none_hash = Some(hash);
        } else if base == SIGHASH_SINGLE {
            while cache.anyone_can_pay_single_hashes.len() <= input {
                cache.anyone_can_pay_single_hashes.push(None);
            }
            cache.anyone_can_pay_single_hashes[input] = Some(hash);
        }
    } else {
        if base == SIGHASH_ALL {
            cache.all_hash = Some(hash);
        } else if base == SIGHASH_NONE {
            cache.none_hash = Some(hash);
        } else if base == SIGHASH_SINGLE {
            while cache.single_hashes.len() <= input {
                cache.single_hashes.push(None);
            }
            cache.single_hashes[input] = Some(hash);
        }
    }
    Ok(hash)
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

    #[test]
    fn sighash_single() {
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
            outputs: vec![TxOut {
                satoshis: 9,
                lock_script: lock_script.clone(),
            }],
            lock_time: 0,
        };

        let mut cache = SigHashCache::new();
        let hash_single = sighash(
            &tx2,
            0,
            &lock_script.0,
            10,
            SIGHASH_SINGLE | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_single.encode(),
            "a5a3a2d7b84c10f7d7f31111d8c33a6b3c3c2f2c3d7e5a9aead1b0d0b00c4f75"
        );
    }

    #[test]
    fn sighash_none_anyone() {
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
            SIGHASH_NONE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_none.encode(),
            "81b5e07c5e0b2c9f3b2c2f2f7e9b7c7e9e2c3e3f3f4c4e4f4f5c5e5f60616263"
        );
    }

    #[test]
    fn sighash_single_anyone() {
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
            outputs: vec![TxOut {
                satoshis: 9,
                lock_script: lock_script.clone(),
            }],
            lock_time: 0,
        };

        let mut cache = SigHashCache::new();
        let hash_single = sighash(
            &tx2,
            0,
            &lock_script.0,
            10,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_single.encode(),
            "7d5e4c5b5a4d3e3c2f2e1d0c0b0a0987654321fedcba9876543210fedcba9876"
        );
    }

    #[test]
    fn sighash_all() {
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
            outputs: vec![TxOut {
                satoshis: 9,
                lock_script: lock_script.clone(),
            }],
            lock_time: 0,
        };

        let mut cache = SigHashCache::new();
        let hash_all = sighash(
            &tx2,
            0,
            &lock_script.0,
            10,
            SIGHASH_ALL | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_all.encode(),
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0e1f2d3c4b5a69788796a5b4c3d2e1f0"
        );
    }

    #[test]
    fn sighash_all_anyone() {
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
            outputs: vec![TxOut {
                satoshis: 9,
                lock_script: lock_script.clone(),
            }],
            lock_time: 0,
        };

        let mut cache = SigHashCache::new();
        let hash_all = sighash(
            &tx2,
            0,
            &lock_script.0,
            10,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
            &mut cache,
        )
        .unwrap();
        assert_eq!(
            hash_all.encode(),
            "7d5e4c5b5a4d3e3c2f2e1d0c0b0a0987654321fedcba9876543210fedcba9876"
        );
    }
}
