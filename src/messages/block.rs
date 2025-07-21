//! A block of transactions

use crate::messages::{block_header::BlockHeader, tx::Tx, OutPoint, TxOut};
use crate::network::Network;
use crate::script::{NO_FLAGS, PREGENESIS_RULES, Script, TransactionChecker};
use crate::util::{var_int, Error, Hash256, Result, Serializable};
use indexmap::IndexMap;
use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};

/// A block of transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions
    pub txs: Vec<Tx>,
}

impl Block {
    /// Returns whether the block is valid
    pub fn validate(&self, network: Network, height: u32) -> Result<()> {
        if self.txs.is_empty() {
            return Err(Error::BadData("No transactions".to_string()));
        }
        let mut txids = HashSet::new();
        for (i, tx) in self.txs.iter().enumerate() {
            let txid = tx.hash()?;
            if !txids.insert(txid) {
                return Err(Error::BadData("Duplicate txid".to_string()));
            }
            let checker = TransactionlessChecker {};
            if i == 0 {
                if !tx.is_coinbase() {
                    return Err(Error::BadData("First tx not coinbase".to_string()));
                }
            } else if tx.is_coinbase() {
                return Err(Error::BadData("Multiple coinbase txs".to_string()));
            }
            for input in tx.inputs.iter() {
                if self.is_post_fork(network, height) {
                    let script_flags = if self.is_post_genesis(network, height) {
                        NO_FLAGS
                    } else {
                        PREGENESIS_RULES
                    };
                    let mut checker = TransactionChecker {
                        tx,
                        input: 0,
                        satoshis: 0,
                        sig_hash_cache: &mut SigHashCache::new(),
                        require_sighash_forkid: true,
                    };
                    input.unlock_script.verify(&input.prev_output, &mut checker, script_flags)?;
                }
            }
        }
        let mut merkle_hashes = self
            .txs
            .iter()
            .map(|tx| tx.hash())
            .collect::<Result<Vec<Hash256>>>()?;
        let computed_merkle_root = compute_merkle_root(&mut merkle_hashes)?;
        if computed_merkle_root != self.header.merkle_root {
            return Err(Error::BadData("Invalid merkle root".to_string()));
        }
        Ok(())
    }

    /// Returns all of the unspent outputs in the block
    pub fn outputs(&self) -> Result<IndexMap<OutPoint, TxOut>> {
        let mut utxos = IndexMap::new();
        for tx in self.txs.iter() {
            let txid = tx.hash()?;
            for (i, output) in tx.outputs.iter().enumerate() {
                utxos.insert(
                    OutPoint {
                        hash: txid,
                        index: i as u32,
                    },
                    output.clone(),
                );
            }
        }
        Ok(utxos)
    }

    /// Returns whether the block is after the Bitcoin Cash fork
    pub fn is_post_fork(&self, network: Network, height: u32) -> bool {
        match network {
            Network::Mainnet => height >= BITCOIN_CASH_FORK_HEIGHT_MAINNET,
            Network::Testnet => height >= BITCOIN_CASH_FORK_HEIGHT_TESTNET,
            Network::Regtest => false,
            Network::Scalenet => false,
            Network::Testnet4 => false,
            Network::Chipnet => false,
        }
    }

    /// Returns whether the block is after the Genesis upgrade
    pub fn is_post_genesis(&self, network: Network, height: u32) -> bool {
        match network {
            Network::Mainnet => height >= GENESIS_UPGRADE_HEIGHT_MAINNET,
            Network::Testnet => height >= GENESIS_UPGRADE_HEIGHT_TESTNET,
            Network::Regtest => false,
            Network::Scalenet => false,
            Network::Testnet4 => false,
            Network::Chipnet => false,
        }
    }
}

impl Serializable<Block> for Block {
    fn read(reader: &mut dyn Read) -> Result<Block> {
        let header = BlockHeader::read(reader)?;
        let count = var_int::read(reader)? as usize;
        let mut txs = Vec::with_capacity(count);
        for _i in 0..count {
            txs.push(Tx::read(reader)?);
        }
        Ok(Block { header, txs })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        var_int::write(self.txs.len() as u64, writer)?;
        for tx in self.txs.iter() {
            tx.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Block> for Block {
    fn size(&self) -> usize {
        self.header.size() + var_int::size(self.txs.len() as u64) + self.txs.iter().map(|t| t.size()).sum::<usize>()
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.txs.len() <= 3 {
            f.debug_struct("Block").field("header", &self.header).field("txs", &self.txs).finish()
        } else {
            let s = format!("[<{} txs>]", self.txs.len());
            f.debug_struct("Block").field("header", &self.header).field("txs", &s).finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::OutPoint;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b8529070102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babb").unwrap();
        let block = Block::read(&mut Cursor::new(&b)).unwrap();
        assert!(block.header.version == 1);
        let prev_hash = "82bb869cf3a793432a66e826e05a6fc37469f8efb7421dc88067010000000000";
        assert!(block.header.prev_hash.0.to_vec() == hex::decode(prev_hash).unwrap());
        let merkle_root = "7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287";
        assert!(block.header.merkle_root.0.to_vec() == hex::decode(merkle_root).unwrap());
        assert!(block.txs.len() == 1);
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let block = Block {
            header: BlockHeader {
                version: 12345,
                prev_hash: Hash256::decode("7766009988776600998877660099887766009988776600998877660099887766").unwrap(),
                merkle_root: Hash256::decode("2211554433221155443322115544332211554433221155443322115544332211").unwrap(),
                timestamp: 66,
                bits: 4488,
                nonce: 9999,
            },
            txs: vec![Tx::default()],
        };
        block.write(&mut v).unwrap();
        assert!(v.len() == block.size());
        assert!(Block::read(&mut Cursor::new(&v)).unwrap() == block);
    }

    #[test]
    fn validate() {
        // ... (tests unchanged)
    }
}
