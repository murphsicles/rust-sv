//! Messages used for Bitcoin peer-to-peer communication

use crate::util::{Error, Result};

pub mod addr;
pub mod block;
pub mod block_header;
pub mod block_locator;
pub mod fee_filter;
pub mod filter_add;
pub mod filter_load;
pub mod headers;
pub mod inv;
pub mod merkle_block;
pub mod message;
pub mod message_header;
pub mod node_addr;
pub mod node_addr_ex;
pub mod out_point;
pub mod ping;
pub mod reject;
pub mod send_cmpct;
pub mod tx;
pub mod version;

pub use self::addr::Addr;
pub use self::block::{Block, BITCOIN_CASH_FORK_HEIGHT_MAINNET, BITCOIN_CASH_FORK_HEIGHT_TESTNET, GENESIS_UPGRADE_HEIGHT_MAINNET, GENESIS_UPGRADE_HEIGHT_TESTNET};
pub use self::block_header::BlockHeader;
pub use self::block_locator::BlockLocator;
pub use self::fee_filter::FeeFilter;
pub use self::filter_add::FilterAdd;
pub use self::filter_load::FilterLoad;
pub use self::headers::Headers;
pub use self::inv::Inv;
pub use self::merkle_block::MerkleBlock;
pub use self::message::{Message, Payload};
pub use self::message_header::MessageHeader;
pub use self::node_addr::NodeAddr;
pub use self::node_addr_ex::NodeAddrEx;
pub use self::out_point::{OutPoint, COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
pub use self::ping::Ping;
pub use self::reject::{Reject, REJECT_CHECKPOINT, REJECT_DUPLICATE, REJECT_DUST, REJECT_INSUFFICIENT_FEE, REJECT_INVALID, REJECT_MALFORMED, REJECT_NONSTANDARD, REJECT_OBSOLETE};
pub use self::send_cmpct::SendCmpct;
pub use self::tx::Tx;
pub use self::tx::{TxIn, TxOut};
pub use self::version::Version;
