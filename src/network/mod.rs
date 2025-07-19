//! Configuration for mainnet and testnet
//!
//! # Examples
//!
//! Iterate through seed nodes:
//!
//! ```no_run, rust
//! use rustsv::network::NetworkConfig;
//!
//! let network = NetworkConfig::new(0).unwrap(); // Mainnet
//! for (ip, port) in network.seed_iter() {
//!     println!("Seed node {:?}:{}", ip, port);
//! }
//! ```

mod network;
mod seed_iter;

pub use self::network::{Network, NetworkConfig};
pub use self::seed_iter::SeedIter;
