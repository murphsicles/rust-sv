use hex::FromHexError;
use ring::error::Unspecified as RingUnspecifiedError;
use base58::FromBase58Error as FromBase58Error;
use secp256k1::Error as Secp256k1Error;
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

/// Standard error type used in the library
#[derive(Debug)]
pub enum Error {
    /// An argument provided is invalid
    BadArgument(String),
    /// The data given is not valid
    BadData(String),
    /// BIP-32 specific error
    Bip32Error(String),
    /// Base58 string could not be decoded
    FromBase58Error(FromBase58Error),
    /// Hex string could not be decoded
    FromHexError(FromHexError),
    /// UTF8 parsing error
    FromUtf8Error(FromUtf8Error),
    /// The state is not valid
    IllegalState(String),
    /// The operation is not valid on this object
    InvalidOperation(String),
    /// Standard library IO error
    IOError(io::Error),
    /// Error parsing an integer
    ParseIntError(ParseIntError),
    /// Error evaluating the script
    ScriptError(String),
    /// Error in the Secp256k1 library
    Secp256k1Error(Secp256k1Error),
    /// The operation timed out
    Timeout,
    /// An unknown error in the Ring library
    UnspecifiedRingError,
    /// The data or functionality is not supported by this library
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::BadArgument(s) => f.write_str(&format!("Bad argument: {}", s)),
            Error::BadData(s) => f.write_str(&format!("Bad data: {}", s)),
            Error::Bip32Error(s) => f.write_str(&format!("BIP-32 error: {}", s)),
            Error::FromBase58Error(e) => f.write_str(&format!("Base58 decoding error: {:?}", e)), // Changed {} to {:?}
            Error::FromHexError(e) => f.write_str(&format!("Hex decoding error: {}", e)),
            Error::FromUtf8Error(e) => f.write_str(&format!("Utf8 parsing error: {}", e)),
            Error::IllegalState(s) => f.write_str(&format!("Illegal state: {}", s)),
            Error::InvalidOperation(s) => f.write_str(&format!("Invalid operation: {}", s)),
            Error::IOError(e) => f.write_str(&format!("IO error: {}", e)),
            Error::ParseIntError(e) => f.write_str(&format!("ParseIntError: {}", e)),
            Error::ScriptError(s) => f.write_str(&format!("Script error: {}", s)),
            Error::Secp256k1Error(e) => f.write_str(&format!("Secp256k1 error: {}", e)),
            Error::Timeout => f.write_str("Timeout"),
            Error::UnspecifiedRingError => f.write_str("Unspecified ring error"),
            Error::Unsupported(s) => f.write_str(&format!("Unsupported: {}", s)),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FromBase58Error(_) => None, // FromBase58Error does not implement Error
            Error::FromHexError(e) => Some(e),
            Error::FromUtf8Error(e) => Some(e),
            Error::IOError(e) => Some(e),
            Error::ParseIntError(e) => Some(e),
            Error::Secp256k1Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FromBase58Error> for Error {
    fn from(e: FromBase58Error) -> Self {
        Error::FromBase58Error(e)
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        Error::FromHexError(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::ParseIntError(e)
    }
}

impl From<Secp256k1Error> for Error {
    fn from(e: Secp256k1Error) -> Self {
        Error::Secp256k1Error(e)
    }
}

impl From<RingUnspecifiedError> for Error {
    fn from(_: RingUnspecifiedError) -> Self {
        Error::UnspecifiedRingError
    }
}

/// Standard Result used in the library
pub type Result<T> = std::result::Result<T, Error>;
