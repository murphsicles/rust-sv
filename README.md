# Rust-SV

A Rust library for building Bitcoin SV applications and infrastructure, providing robust tools for P2P networking, address handling, transaction processing, and more.

[![Crates.io](https://img.shields.io/crates/v/sv.svg)](https://crates.io/crates/sv)
[![Documentation](https://docs.rs/sv/badge.svg)](https://docs.rs/sv/)
[![Dependencies](https://deps.rs/repo/github/murphsicles/rust-sv/status.svg)](https://deps.rs/repo/github/murphsicles/rust-sv)
[![Build Status](https://github.com/murphsicles/rust-sv/actions/workflows/rust.yml/badge.svg)](https://github.com/murphsicles/rust-sv/actions)

## Features

- **P2P Protocol**: Construct and serialize messages for Bitcoin SV's peer-to-peer network.
- **Address Handling**: Encode/decode base58 addresses for P2PKH and P2SH (e.g., `addr_encode`, `addr_decode`).
- **Transaction Signing**: Create and sign transactions with Bitcoin SV scripts.
- **Script Evaluation**: Execute and validate Bitcoin SV scripts.
- **Node Connections**: Establish connections to Bitcoin SV nodes with basic message handling.
- **Wallet Support**: Derive keys and parse mnemonics for wallet applications.
- **Network Support**: Full compatibility with Mainnet and Testnet, including Genesis upgrade.
- **Primitives**: Utilities for hashes (`Hash160`, `sha256d`), and other Bitcoin SV primitives.

## Installation

Add `rust-sv` to your `Cargo.toml`:

```toml
[dependencies]
rustsv = "0.4.2"
```

Or use the latest development version:

```toml
[dependencies]
sv = { git = "https://github.com/murphsicles/rust-sv", branch = "master" }
```

### System Requirements

- Rust: Stable (1.82 or later)
- Dependencies: `libzmq3-dev`, `libpq-dev` (for projects like `RustBus`)
- OS: Linux, macOS, or Windows (Linux recommended for production)

Install dependencies on Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y libzmq3-dev
```

## Usage

### Encode a Base58 Address

```rust
use rustsv::wallet::adressing::{addr_encode, AddressType};
use rustsv::network::Network;
use rustsv::util::hash160;

let pubkeyhash = hash160(&[0; 33]);
let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
println!("Address: {}", addr);
```

### Decode a Base58 Address

```rust
use rustsv::wallet::adressing::addr_decode;
use rustsv::network::Network;

let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
println!("Pubkey Hash: {:?}", pubkeyhash);
println!("Address Type: {:?}", addr_type);
```

### Connect to a Bitcoin SV Node

```rust
use rustsv::network::Network;
use rustsv::node::Node;
use async_std::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:8333").await?;
    let mut node = Node::new(stream, Network::Mainnet, None)?;
    let version = node.handshake().await?;
    println!("Connected to node with version: {}", version);
    Ok(())
}
```

More examples are available in the [examples directory](examples/).

## Building and Testing

Clone the repository and run tests:

```bash
git clone https://github.com/murphsicles/rust-sv.git
cd rust-sv
cargo test -- --nocapture
```

Build the library:

```bash
cargo build --release
```

## Known Limitations

- **Consensus Code**: This library is not currently suitable for consensus-critical applications due to incomplete validation checks. (Coming Soon)
- **Performance**: Some features (e.g., script evaluation) may require optimization for high-throughput use cases.
- **ZMQ Dependency**: Node connections may require a running Bitcoin SV node with ZMQ enabled.

## Related Projects

- [RustBus](https://github.com/murphsicles/RustBus): The Legendary BSV Microservices Engine built with `rust-sv`.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit changes (`git commit -m "Add my feature"`).
4. Push to the branch (`git push origin feature/my-feature`).
5. Open a Pull Request.

Report issues at [GitHub Issues](https://github.com/murphsicles/rust-sv/issues).

## License

`rust-sv` is licensed under the [MIT License](LICENSE).

## Acknowledgments

- Built for the BSV blockchain community by [murphsicles](https://github.com/murphsicles).
- Inspired by Bitcoin SV's commitment to massive on-chain scaling.
