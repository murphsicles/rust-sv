# Rust-SV Documentation

## Overview

Rust-SV is a Rust library providing a foundation for building applications on Bitcoin SV (BSV) using Rust. It offers robust tools for P2P networking, address handling, transaction processing, script evaluation, node connections, wallet management, and various utility functions. The library supports both Mainnet and Testnet, including compatibility with the Genesis upgrade.

### Key Features

- **P2P Protocol**: Construct, serialize, and deserialize messages for the Bitcoin SV peer-to-peer network.
- **Address Handling**: Encode and decode Base58 addresses for Pay-to-PubKey-Hash (P2PKH) and Pay-to-Script-Hash (P2SH).
- **Transaction Signing**: Create and sign transactions using BSV scripts.
- **Script Evaluation**: Execute and validate Bitcoin SV scripts.
- **Node Connections**: Establish and manage connections to BSV nodes with message handling.
- **Wallet Support**: Derive keys and parse mnemonics for wallet applications using BIP-32 and BIP-39.
- **Network Support**: Configurations for Mainnet and Testnet, including seed node iteration.
- **Primitives**: Utilities for hashing (e.g., Hash160, SHA256d), bloom filters, variable integers, serialization, and reactive programming.

## Installation

Add the following to your `Cargo.toml`:

    [dependencies]
    sv = "0.4.1"

For the development version:

    [dependencies]
    sv = { git = "https://github.com/murphsicles/rust-sv", branch = "master" }

### System Requirements

- Rust: Stable version 1.82 or later.
- Dependencies: May require system libraries like `libzmq3-dev` for related features.
- Operating Systems: Linux (recommended), macOS, Windows.

## Crates

The primary crate is `sv`, a library crate with no additional workspace crates evident from the structure. Dependencies and exact versions are managed via Cargo.toml, but typical ones include those for serialization (`bytes`), cryptography (`secp256k1`, `rand`), hashing (`sha2`, `ripemd160`), networking (`tokio` or `async-std`), and others based on features like bloom filters and reactive utilities.

## Internal Structure

The library is modular, with each module focusing on a specific domain. Below is a detailed description of each module, including public types, traits, functions, constants, and examples drawn directly from the documentation. Submodules are noted where applicable.

### Main Library Entry (`src/lib.rs`)

This serves as the crate root, declaring public modules. Public modules include:

- `address`: Address encoding and decoding.
- `messages`: Peer-to-peer network protocol messages.
- `network`: Configuration for mainnet and testnet.
- `peer`: Node connection and message handling.
- `script`: Script opcodes and interpreter.
- `transaction`: Build and sign transactions.
- `util`: Miscellaneous helpers.
- `wallet`: Wallet and key management.

No root-level re-exports or additional types are specified.

### Address Module (`src/address/`)

Handles encoding and decoding of BSV addresses.

**Public Enums**:
- `AddressType`: Represents address type, either P2PKH or P2SH.

**Public Functions**:
- `addr_decode(addr: &str, network: Network) -> Result<(Vec<u8>, AddressType), Error>`: Decodes a Base58 address to a public key hash and type.
  - Example:
    ```rust
    use sv::address::addr_decode;
    use sv::network::Network;

    let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
    let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
    ```
- `addr_encode(pubkeyhash: &[u8], addr_type: AddressType, network: Network) -> String`: Encodes a public key hash to a Base58 address.
  - Example:
    ```rust
    use sv::address::{addr_encode, AddressType};
    use sv::network::Network;
    use sv::util::hash160;

    let pubkeyhash = hash160(&[0; 33]);
    let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
    ```
### Messages Module (`src/messages/`)

Defines P2P network messages, including serialization and deserialization.

**Public Structs**:
- `Addr`: Known node addresses.
- `Block`: Block of transactions.
- `BlockHeader`: Block header.
- `BlockLocator`: Specifies which blocks to return.
- `FeeFilter`: Specifies the minimum transaction fee this node accepts.
- `FilterAdd`: Adds a data element to the bloom filter.
- `FilterLoad`: Loads a bloom filter using specified parameters.
- `Headers`: Collection of block headers.
- `Inv`: Inventory payload describing objects a node knows about.
- `InvVect`: Inventory vector describing an object.
- `MerkleBlock`: Block header and partial Merkle tree for SPV.
- `MessageHeader`: Header for all messages.
- `NodeAddr`: Network address for a node.
- `NodeAddrEx`: Extended node address with last connected time.
- `OutPoint`: Reference to a transaction output.
- `Ping`: Ping or pong payload.
- `Reject`: Rejected message.
- `SendCmpct`: Specifies if compact blocks are supported.
- `Tx`: Bitcoin transaction.
- `TxIn`: Transaction input.
- `TxOut`: Transaction output.
- `Version`: Version payload defining node capabilities.

**Public Enums**:
- `Message`: Enum for all P2P messages (e.g., `Message::Headers(headers)`).

**Submodules**:
- `commands`: Message commands for headers.

**Constants** (selected):
- `BLOOM_UPDATE_ALL`, `BLOOM_UPDATE_NONE`, `BLOOM_UPDATE_P2PUBKEY_ONLY`: Bloom filter update flags.
- `COINBASE_OUTPOINT_HASH`, `COINBASE_OUTPOINT_INDEX`: For coinbase transactions.
- `INV_VECT_BLOCK`, `INV_VECT_TX`, etc.: Inventory types.
- `MAX_INV_ENTRIES`, `MAX_PAYLOAD_SIZE`: Limits.

**Examples**:
- Decoding a message:
    use sv::messages::Message;
    use sv::network::Network;
    use std::io::Cursor;

    let bytes = [/* byte array */];
    let magic = Network::Mainnet.magic();
    let message = Message::read(&mut Cursor::new(&bytes), magic).unwrap();
    match message {
        Message::Headers(headers) => { /* handle */ },
        _ => { /* other */ }
    }
- Constructing a transaction:
    use sv::messages::{OutPoint, Tx, TxIn, TxOut};
    use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
    use sv::util::{hash160, Hash256};

    // ... (construct inputs and outputs)
    let tx = Tx { version: 2, inputs, outputs, lock_time: 0 };

### Network Module (`src/network/`)

Provides network configurations and seed node iteration.

**Public Enums**:
- `Network`: Network type (Mainnet, Testnet).

**Public Structs**:
- `SeedIter`: Iterates through DNS seeds semi-randomly.

**Methods** (inferred from examples):
- `Network::seed_iter() -> SeedIter`: Returns an iterator over seed nodes.
  - Example:
    ```rust
    use sv::network::Network;

    for (ip, port) in Network::Mainnet.seed_iter() {
        println!("Seed node {:?}:{}", ip, port);
    }
    ```
### Peer Module (`src/peer/`)

Manages node connections and message handling.

**Public Structs**:
- `Peer`: Node on the network for sending/receiving messages.
- `PeerConnected`: Event for connection established.
- `PeerDisconnected`: Event for connection terminated.
- `PeerMessage`: Event for received network message.
- `SVPeerFilter`: Filters peers to Bitcoin SV full nodes.

**Public Traits**:
- `PeerFilter`: Filters peers based on version info.

**Methods** (from examples):
- `Peer::connect(ip, port, network: Network, version: Version, filter: SVPeerFilter) -> Peer`: Connects to a peer.
- `peer.send(&message) -> Result<()>`: Sends a message.
- `peer.connected_event() -> Observable<PeerConnected>`: Observable for connection events.
- Similar for `disconnected_event()`, `messages()`.

**Examples**:
- Synchronous send/receive:
    ```rust
    use sv::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
    use sv::network::Network;
    use sv::peer::{Peer, SVPeerFilter};
    use sv::util::rx::Observable;
    use sv::util::secs_since;
    use std::time::UNIX_EPOCH;

    // ... (create version)
    let peer = Peer::connect(ip, port, Network::Mainnet, version, SVPeerFilter::new(0));
    peer.connected_event().poll();
    let ping = Message::Ping(Ping { nonce: 0 });
    peer.send(&ping).unwrap();
    let response = peer.messages().poll();
    ```
- Asynchronous event handling (using observers).

### Script Module (`src/script/`)

Handles script opcodes and interpretation.

**Public Structs**:
- `Script`: Transaction script.
- `TransactionChecker`: Checks external values for transaction spends.
- `TransactionlessChecker`: Fails all transaction checks.

**Public Traits**:
- `Checker`: Checks external values in scripts.

**Submodules**:
- `op_codes`: Script commands.

**Constants**:
- `NO_FLAGS`: Execute with genesis rules.
- `PREGENESIS_RULES`: Flag for pre-genesis rules.

**Methods** (from examples):
- `script.eval(&mut checker, flags) -> Result<()>`: Evaluates a script.

**Examples**:
- Evaluate a simple script:
    ```rust
    use sv::script::op_codes::*;
    use sv::script::{Script, TransactionlessChecker, NO_FLAGS};

    let mut script = Script::new();
    script.append(OP_10);
    script.append(OP_5);
    script.append(OP_DIV);

    script.eval(&mut TransactionlessChecker {}, NO_FLAGS).unwrap();
    ```
### Transaction Module (`src/transaction/`)

Supports building and signing transactions.

**Public Functions**:
- `generate_signature(private_key: &[u8;32], sighash: &Hash256, sighash_type: u32) -> Result<Vec<u8>>`: Generates a signature for a sighash.

**Submodules**:
- `p2pkh`: Pay-to-public-key-hash scripts (e.g., `create_lock_script`, `create_unlock_script`).
- `sighash`: Sighash helpers (e.g., `sighash`, `SigHashCache`).

**Examples**:
- Signing a transaction:
    ```
    use sv::messages::{Tx, TxIn};
    use sv::transaction::generate_signature;
    use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
    use sv::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_NONE};
    use sv::util::{hash160};

    // ... (create tx, cache, sighash)
    let signature = generate_signature(&private_key, &sighash, sighash_type).unwrap();
    tx.inputs[0].unlock_script = create_unlock_script(&signature, &public_key);
    ```
### Util Module (`src/util/`)

Miscellaneous helpers.

**Public Structs**:
- `BloomFilter`: Bloom filter for SPV nodes.
- `Hash160`: 160-bit hash for addresses.
- `Hash256`: 256-bit hash for blocks/transactions.

**Public Enums**:
- `Error`: Standard error type.

**Public Traits**:
- `Serializable`: For serialization/deserialization.

**Public Functions**:
- `hash160(data: &[u8]) -> Hash160`: Computes RIPEMD160(SHA256(data)).
- `sha256d(data: &[u8]) -> Hash256`: Computes double SHA256.
- `secs_since(time: SystemTime) -> u64`: Seconds since a past time.

**Type Aliases**:
- `Result<T>`: `std::result::Result<T, Error>`.

**Constants** (selected):
- `BITCOIN_CASH_FORK_HEIGHT_MAINNET`, `GENESIS_UPGRADE_HEIGHT_MAINNET`: Fork heights.
- `BLOOM_FILTER_MAX_FILTER_SIZE`, `BLOOM_FILTER_MAX_HASH_FUNCS`: Bloom limits.

**Submodules**:
- `rx`: Lightweight reactive library (e.g., `Observable`, `Observer`).

### Wallet Module (`src/wallet/`)

Wallet and key management using BIP-32/BIP-39/BIP-44.

**Public Structs**:
- `ExtendedKey`: Private or public key in HD wallet.

**Public Enums**:
- `ExtendedKeyType`: Public or private key type.
- `Wordlist`: Wordlist language.

**Public Functions**:
- `derive_extended_key(...)`: Derives a key using BIP-32/BIP-44 notation.
- `load_wordlist(language: Wordlist) -> Vec<String>`: Loads wordlist for a language.
- `mnemonic_decode(mnemonic: &str, wordlist: &Wordlist) -> Result<Vec<u8>>`: Decodes mnemonic to data (BIP-39).
- `mnemonic_encode(data: &[u8], wordlist: &Wordlist) -> Result<String>`: Encodes data to mnemonic (BIP-39).

**Constants**:
- `HARDENED_KEY`: Index for hardened keys.
- `MAINNET_PRIVATE_EXTENDED_KEY` ("xprv"), etc.: Prefixes for extended keys.

Wordlists are included for multiple languages (e.g., english.txt).

## Additional Files

- **.github/workflows/**: CI pipelines for publishing and testing.
- `.gitignore`, `CHANGELOG.md`, `LICENSE` (MIT), `README.md`: Standard project files.

This documentation is comprehensive, based on the library's structure and API as documented. For implementation details or updates, refer to the source code or generated docs.
