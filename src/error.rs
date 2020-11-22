//! LDAP errors

use der_parser::error::BerError;
use nom::error::{ErrorKind, FromExternalError, ParseError};
use nom::IResult;

/// Holds the result of parsing functions (LDAP)
///
/// Note that this type is also a `Result`, so usual functions (`map`, `unwrap` etc.) are available.
///
/// Note that this type is not named `LdapResult` to avoid conflicts with LDAP standard type
pub type Result<'a, T> = IResult<&'a [u8], T, LdapError>;

/// An error that can occur while parsing or validating a certificate.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum LdapError {
    #[error("Invalid LDAP String encoding")]
    InvalidString,

    #[error("Invalid LDAP Authentication Type")]
    InvalidAuthenticationType,

    #[error("Invalid DN encoding")]
    InvalidDN,

    #[error("Invalid Substring Type")]
    InvalidSubstring,

    #[error("Invalid Type for Filter")]
    InvalidFilterType,
    #[error("Invalid Type for Message")]
    InvalidMessageType,

    #[error("Unknown error")]
    Unknown,

    #[error("BER error: {0}")]
    Ber(#[from] BerError),
    #[error("nom error: {0:?}")]
    NomError(ErrorKind),
}

impl From<LdapError> for nom::Err<LdapError> {
    fn from(e: LdapError) -> nom::Err<LdapError> {
        nom::Err::Error(e)
    }
}

impl From<ErrorKind> for LdapError {
    fn from(e: ErrorKind) -> LdapError {
        LdapError::NomError(e)
    }
}

impl<I> ParseError<I> for LdapError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        LdapError::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        LdapError::NomError(kind)
    }
}

impl<I, E> FromExternalError<I, E> for LdapError {
    fn from_external_error(_input: I, kind: ErrorKind, _e: E) -> LdapError {
        LdapError::NomError(kind)
    }
}

#[allow(dead_code)]
pub(crate) fn print_hex_dump(bytes: &[u8], max_len: usize) {
    use nom::HexDisplay;
    use std::cmp::min;
    let m = min(bytes.len(), max_len);
    if m == 0 {
        println!("<empty>");
    }
    print!("{}", &bytes[..m].to_hex(16));
    if bytes.len() > max_len {
        println!("... <continued>");
    }
}
