use thiserror::Error;
use hex::FromHexError;
use base58::FromBase58Error as FromBase58Error;
use secp256k1::Error as Secp256k1Error;
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

/// Standard error type used in the library
#[derive(Error, Debug)]
pub enum Error {
    /// An argument provided is invalid
    #[error("Bad argument: {0}")]
    BadArgument(String),
    /// The data given is not valid
    #[error("Bad data: {0}")]
    BadData(String),
    /// Base58 string could not be decoded
    #[error("Base58 decoding error: {0:?}")]
    FromBase58Error(FromBase58Error),
    /// Hex string could not be decoded
    #[error("Hex decoding error: {0}")]
    FromHexError(FromHexError),
    /// UTF8 parsing error
    #[error("Utf8 parsing error: {0}")]
    FromUtf8Error(FromUtf8Error),
    /// The state is not valid
    #[error("Illegal state: {0}")]
    IllegalState(String),
    /// The operation is not valid on this object
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// Standard library IO error
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
    /// Error parsing an integer
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),
    /// Error evaluating the script
    #[error("Script error: {0}")]
    ScriptError(String),
    /// Error in the Secp256k1 library
    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),
    /// The operation timed out
    #[error("Timeout")]
    Timeout,
    /// The data or functionality is not supported by this library
    #[error("Unsupported: {0}")]
    Unsupported(String),
}

/// Standard Result used in the library
pub type Result<T> = std::result::Result<T, Error>;
