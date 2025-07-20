use crate::messages::message::Payload;
use crate::util::{var_int, Error, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io;
use std::io::{Read, Write};

/// Maximum number of inventory vectors
const MAX_INV_COUNT: u64 = 50000;

/// Inventory vector type for transactions
pub const INV_TYPE_TX: u32 = 1;

/// Inventory vector type for blocks
pub const INV_TYPE_BLOCK: u32 = 2;

/// Inventory vector type for filtered blocks
pub const INV_TYPE_FILTERED_BLOCK: u32 = 3;

/// Inventory vector type for compact blocks
pub const INV_TYPE_CMPCT_BLOCK: u32 = 4;

/// Inventory vector
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct InvVector {
    /// Type of object
    pub inv_type: u32,
    /// Object hash
    pub hash: Hash256,
}

/// Collection of inventory vectors
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Inv {
    /// List of inventory vectors
    pub invs: Vec<InvVector>,
}

impl Inv {
    /// Returns whether the inventory message is valid
    pub fn validate(&self) -> Result<()> {
        if self.invs.len() as u64 > MAX_INV_COUNT {
            return Err(Error::BadData("Too many invs".to_string()));
        }
        for inv in self.invs.iter() {
            match inv.inv_type {
                INV_TYPE_TX | INV_TYPE_BLOCK | INV_TYPE_FILTERED_BLOCK | INV_TYPE_CMPCT_BLOCK => {}
                _ => {
                    return Err(Error::BadData(format!("Invalid inv type: {}", inv.inv_type)));
                }
            }
        }
        Ok(())
    }
}

impl Serializable<Inv> for Inv {
    fn read(reader: &mut dyn Read) -> Result<Inv> {
        let count = var_int::read(reader)?;
        if count > MAX_INV_COUNT {
            let msg = format!("Too many invs: {}", count);
            return Err(Error::BadData(msg));
        }
        let mut invs = Vec::with_capacity(count as usize);
        for _i in 0..count {
            let inv_type = reader.read_u32::<LittleEndian>()?;
            let hash = Hash256::read(reader)?;
            invs.push(InvVector { inv_type, hash });
        }
        Ok(Inv { invs })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.invs.len() as u64, writer)?;
        for inv in self.invs.iter() {
            writer.write_u32::<LittleEndian>(inv.inv_type)?;
            inv.hash.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Inv> for Inv {
    fn size(&self) -> usize {
        var_int::size(self.invs.len() as u64) + self.invs.len() * (4 + 32)
    }
}

impl fmt::Debug for Inv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.invs.len() <= 3 {
            f.debug_struct("Inv").field("invs", &self.invs).finish()
        } else {
            let s = format!("[<{} invs>]", self.invs.len());
            f.debug_struct("Inv").field("invs", &s).finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::io::Cursor;

    #[test]
    fn read_bytes() {
        let b = hex::decode("0201000000e4b883e5bda9e7a59ee4bb99e9b1bc3c337a8b8c462e7e1d8e6b39f6c6c0a901000000e4b883e5bda9e7a59ee4bb99e9b1bc3c337a8b8c462e7e1d8e6b39f6c6c0a9").unwrap();
        let inv = Inv::read(&mut Cursor::new(&b)).unwrap();
        assert!(inv.invs.len() == 2);
        assert!(inv.invs[0].inv_type == INV_TYPE_TX);
        assert!(inv.invs[0].hash == Hash256::decode("a9c0c6f6396b8e1d7e2e468c8b7a333cbc1b9e99bbe49ea597e7a9bde583b8e4").unwrap());
        assert!(inv.invs[1].inv_type == INV_TYPE_TX);
        assert!(inv.invs[1].hash == Hash256::decode("a9c0c6f6396b8e1d7e2e468c8b7a333cbc1b9e99bbe49ea597e7a9bde583b8e4").unwrap());
    }

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let inv = Inv {
            invs: vec![
                InvVector {
                    inv_type: INV_TYPE_BLOCK,
                    hash: Hash256::decode("7766009988776600998877660099887766009988776600998877660099887766").unwrap(),
                },
                InvVector {
                    inv_type: INV_TYPE_TX,
                    hash: Hash256::decode("1122334455112233445511223344551122334455112233445511223344551122").unwrap(),
                },
            ],
        };
        inv.write(&mut v).unwrap();
        assert!(v.len() == inv.size());
        assert!(Inv::read(&mut Cursor::new(&v)).unwrap() == inv);
    }

    #[test]
    fn validate() {
        let inv = Inv {
            invs: vec![InvVector {
                inv_type: INV_TYPE_TX,
                hash: Hash256([0; 32]),
            }],
        };
        assert!(inv.validate().is_ok());

        let inv = Inv {
            invs: vec![InvVector {
                inv_type: 999,
                hash: Hash256([0; 32]),
            }],
        };
        assert!(inv.validate().is_err());
    }
}
