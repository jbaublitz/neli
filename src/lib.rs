//! # Type safety for the weary netlink user
//!
//! ## Rationale
//!
//! This crate aims to be a pure Rust implementation that defines
//! the necessary constants and wraps them in enums to distinguish between various categories of
//! constants in the context of netlink.
//!
//! ## The project is broken down into the following modules:
//! * `consts` - This is where all of the C-defined constants are wrapped into type safe enums for
//! use in the library.
//! * `err` - This module contains all of the protocol and library-level errors encountered in the
//! code.
//! * `genl` - This code provides parsing for the generic netlink subsystem of the netlink
//! protocol.
//! * `netfilter` - Netfilter related protocols (NFLOG, NFQUEUE, CONNTRACK).
//! * `nlattr` - This code provides more granular parsing methods for the generic netlink
//! attributes in the context of generic netlink requests and responses.
//! * `nl` - This is the top level netlink header code that handles the header that all netlink
//! messages are encapsulated in.
//! * `rtnl` - This module is for the routing netlink subsystem of the netlink protocol.
//! * `socket` - This provides a socket structure for use in sending and receiving messages and a
//! number of convenience functions for commonly encountered use cases.
//!
//! ## Traits
//!
//! The library at the top level contains the `Nl` trait which provides a buffer size calculation
//! function, a serialization method, and a deserialization method. It also contains
//! implementations of `Nl` for common types. The is one additional trait, `NlBuf`, used in cases
//! where, to deserialize a type, a buffer needs to be provided by the caller function and passed
//! to the callee.
//!
//! ## Design decisions
//!
//! This is a fairly low level library that currently does not have a whole lot of higher level
//! handle-type data structures and relies mostly on the `NlSocket` struct to provide most of the
//! convenience functions. I hope to add a higher level API by `v0.5.0` to ease some of the
//! workflows that have been brought to my attention.
//!
//! The goal of this library is completeness for handling netlink and am working to incorporate
//! features that will make this library easier to use in all use cases. If you have a use case you
//! would like to see supported, please open an issue on github.
//!
//! ## Examples
//!
//! Examples of working code exist in the `examples/` subdirectory on Github. They have a separate
//! `Cargo.toml` file to provide easy testing and use.
//!
//! ## Documentation
//!
//! Each module has been documented extensively to provide information on how to use the code
//! contained in the module. Pull requests for documentation mistakes, updates, and rewording for
//! clarity is a valuable contribution as this project aims to be as simple to use as
//! possible.

#![deny(missing_docs)]

#[macro_use]
mod macros;

/// C constants defined as types
pub mod consts;
/// Error module
pub mod err;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genl;
/// Utilities for iterating through netlink responses
pub mod iter;
mod neli_constants;
/// Nflog protocol (logging for netfilter)
//#[cfg(feature = "netfilter")]
//pub mod netfilter;
/// Top-level netlink header
pub mod nl;
/// Netlink attribute handler
pub mod nlattr;
mod parse;
/// Route netlink bindings
pub mod rtnl;
/// Wrapper for `libc` sockets
pub mod socket;
/// Buffer types for various operations
pub mod types;
// Module for high level stream interface
//pub mod stream;
/// Module with helper methods and data structures
pub mod utils;

use std::{io::Write, mem, str};

use byteorder::ByteOrder;
#[cfg(feature = "logging")]
use lazy_static::lazy_static;

pub use crate::neli_constants::MAX_NL_LENGTH;
use crate::{
    consts::alignto,
    err::{DeError, SerError, SerErrorKind, WrappedError},
    types::{Buffer, BufferOps, DeBuffer, DeBufferOps, SerBuffer, SerBufferOps},
};

#[cfg(feature = "logging")]
lazy_static! {
    static ref LOGGING_INITIALIZED: bool =
        simple_logger::init_with_level(log::Level::Debug).is_ok();
    static ref SHOW_LOGS: bool = std::env::var("NELI_LOG").is_ok();
}

/// Logging mechanism for neli for debugging
#[cfg(feature = "logging")]
#[macro_export]
macro_rules! log {
    ($fmt:tt, $($args:expr),*) => {
        if *$crate::LOGGING_INITIALIZED && *$crate::SHOW_LOGS {
            log::debug!(concat!($fmt, "\n{}"), $($args),*, ["-"; 80].join(""));
        } else {
            println!(concat!($fmt, "\n{}"), $($args),*, ["-"; 80].join(""));
        }
    }
}

/// Trait defining basic actions required for netlink communication.
/// Implementations for basic and `neli`'s types are provided (see below). Create new
/// implementations if you have to work with a Netlink API that uses
/// values of more unusual types.
pub trait Nl: Sized {
    /// Serialization method
    fn serialize<'a>(&self, m: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>>;

    /// Deserialization method
    fn deserialize(m: DeBuffer) -> Result<Self, DeError>;

    /// The size of the binary representation of a type not aligned to work size
    fn type_size() -> Option<usize>;

    /// The size of the binary representation of a type not aligned to work size
    fn type_asize() -> Option<usize> {
        Self::type_size().map(alignto)
    }

    /// The size of the binary representation of an existing value not aligned to word size
    fn size(&self) -> usize;

    /// The size of the binary representation of an existing value aligned to word size
    fn asize(&self) -> usize {
        alignto(self.size())
    }

    /// Pad the data serialized data structure to alignment
    fn pad<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        let padding_len = self.asize() - self.size();
        if let Err(e) = mem
            .as_mut()
            .write_all(&[0; libc::NLA_ALIGNTO as usize][..padding_len])
        {
            Err(SerError::new_with_kind(
                SerErrorKind::Wrapped(WrappedError::IOError(e)),
                mem,
            ))
        } else {
            Ok(mem)
        }
    }
}

/// `Nl::deserialize()` alternative with lifetimes.
pub trait NlBorrowed<'a>: Sized + Nl {
    /// Deserialization method with byte slice
    fn deserialize_borrowed(m: DeBuffer<'a>) -> Result<Self, DeError> {
        Self::deserialize(m)
    }
}

impl Nl for u8 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        let size = self.size();
        match mem.len() {
            i if i < size => return Err(SerError::new_with_kind(SerErrorKind::UnexpectedEOB, mem)),
            i if i > size => {
                return Err(SerError::new_with_kind(SerErrorKind::BufferNotFilled, mem))
            }
            _ => (),
        };
        let _ = mem.as_mut().write(&[*self]);
        Ok(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let size = Self::type_size().expect("Integers have static size");
        match mem.len() {
            i if i < size => return Err(DeError::UnexpectedEOB),
            i if i > size => return Err(DeError::BufferNotParsed),
            _ => (),
        };
        Ok(*mem.as_ref().get(0).expect("Length already checked"))
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u8>())
    }
}

impl Nl for u16 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(put_int!(*self, mem, write_u16))
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u16))
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u16>())
    }
}

impl Nl for u32 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(put_int!(*self, mem, write_u32))
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u32))
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u32>())
    }
}

impl Nl for i32 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(put_int!(*self, mem, write_i32))
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_i32))
    }

    fn size(&self) -> usize {
        mem::size_of::<i32>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<i32>())
    }
}

impl Nl for u64 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(put_int!(*self, mem, write_u64))
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u64))
    }

    fn size(&self) -> usize {
        mem::size_of::<u64>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u64>())
    }
}

/// A `u64` data type that will always be serialized as big endian
#[derive(Copy, Debug, Clone)]
pub struct BeU64(u64);

impl BeU64 {
    /// Create a big endian `u64` type from a native endian `u64`
    pub fn new(v: u64) -> Self {
        BeU64(v)
    }

    /// As native endian `u64`
    pub fn as_ne_u64(self) -> u64 {
        self.0
    }
}

impl Nl for BeU64 {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        Ok(put_int!(self.0, mem, write_u64, byteorder::BE))
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(BeU64(get_int!(mem, read_u64, byteorder::BE)))
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn type_size() -> Option<usize> {
        u64::type_size()
    }
}

impl<'a> Nl for &'a [u8] {
    fn serialize<'b>(&self, mut mem: SerBuffer<'b>) -> Result<SerBuffer<'b>, SerError<'b>> {
        let size = self.size();
        match mem.len() {
            i if i > size => {
                return Err(SerError::new_with_kind(SerErrorKind::BufferNotFilled, mem))
            }
            i if i < size => return Err(SerError::new_with_kind(SerErrorKind::UnexpectedEOB, mem)),
            _ => (),
        };
        if let Err(e) = mem.as_mut().write_all(self) {
            Err(SerError::new_with_kind(
                SerErrorKind::Wrapped(WrappedError::from(e)),
                mem,
            ))
        } else {
            Ok(mem)
        }
    }

    fn deserialize(_m: DeBuffer) -> Result<Self, DeError> {
        unimplemented!()
    }

    fn size(&self) -> usize {
        self.len()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

impl Nl for Buffer {
    fn serialize<'a>(&self, mut mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        if let Err(e) = mem.as_mut().write(self.as_ref()) {
            Err(SerError::new_with_kind(
                SerErrorKind::Wrapped(WrappedError::from(e)),
                mem,
            ))
        } else {
            Ok(mem)
        }
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(Buffer::from_slice(mem.as_ref()))
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for Vec<u8> {
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        self.as_slice().serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(mem.as_ref().to_vec())
    }

    fn size(&self) -> usize {
        self.len()
    }

    fn type_size() -> Option<usize> {
        None
    }
}

impl<'a> Nl for &'a str {
    fn serialize<'b>(&self, mut mem: SerBuffer<'b>) -> Result<SerBuffer<'b>, SerError<'b>> {
        let size = self.size();
        match mem.len() {
            i if i > size => {
                return Err(SerError::new_with_kind(SerErrorKind::BufferNotFilled, mem))
            }
            i if i < size => return Err(SerError::new_with_kind(SerErrorKind::UnexpectedEOB, mem)),
            _ => (),
        }
        match mem.as_mut().write(self.as_bytes()) {
            Ok(write_size) => {
                assert_eq!(write_size + 1, size);
                mem.as_mut()[write_size] = 0;
                Ok(mem)
            }
            Err(e) => Err(SerError::new_with_kind(
                SerErrorKind::Wrapped(WrappedError::IOError(e)),
                mem,
            )),
        }
    }

    fn deserialize(_: DeBuffer) -> Result<Self, DeError> {
        unimplemented!()
    }

    fn size(&self) -> usize {
        self.len() + 1
    }

    fn type_size() -> Option<usize> {
        None
    }
}

impl Nl for String {
    fn serialize<'a>(&self, mem: SerBuffer<'a>) -> Result<SerBuffer<'a>, SerError<'a>> {
        self.as_str().serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let last_elem = mem.len() - 1;
        match mem.as_ref().get(last_elem) {
            Some(0) => (),
            _ => return Err(DeError::NullError),
        };
        String::from_utf8((&mem.as_ref()[..last_elem]).to_vec()).map_err(DeError::new)
    }

    fn size(&self) -> usize {
        self.len() + 1
    }

    fn type_size() -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::mem::size_of;

    #[test]
    fn test_nl_u8() {
        let v = 5u8;
        let mut ser_buffer = SerBuffer::new(Some(size_of::<u8>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref()[0], v);

        let s = DeBuffer::from(&[5u8] as &[u8]);
        let de = u8::deserialize(s).unwrap();
        assert_eq!(de, 5)
    }

    #[test]
    fn test_nl_u16() {
        let v = 6000u16;
        let desired_buffer = v.to_ne_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<u16>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);

        let de = u16::deserialize(DeBuffer::from(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 6000);
    }

    #[test]
    fn test_nl_i32() {
        let v = 600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<i32>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);

        let de = i32::deserialize(DeBuffer::from(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 600_000);

        let v = -600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<i32>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);

        let de = i32::deserialize(DeBuffer::from(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, -600_000)
    }

    #[test]
    fn test_nl_u32() {
        let v = 600_000u32;
        let desired_buffer = v.to_ne_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<u32>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);

        let de = u32::deserialize(DeBuffer::from(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 600_000)
    }

    #[test]
    fn test_nl_u64() {
        let v = 12_345_678_901_234u64;
        let desired_buffer = v.to_ne_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<u64>()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);

        let de = u64::deserialize(DeBuffer::from(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 12_345_678_901_234);
    }

    #[test]
    fn test_nl_be_u64() {
        let v = 571_987_654u64;
        let desired_buffer = v.to_be_bytes();
        let mut ser_buffer = SerBuffer::new(Some(size_of::<u64>()));
        ser_buffer = BeU64(v).serialize(ser_buffer).unwrap();
        assert_eq!(ser_buffer.as_ref(), &desired_buffer);
    }

    #[test]
    fn test_nl_slice() {
        let v: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut ser_buffer = SerBuffer::new(Some(v.len()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(v, ser_buffer.as_ref());
    }

    #[test]
    fn test_nl_vec() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut ser_buffer = SerBuffer::new(Some(v.len()));
        ser_buffer = v.serialize(ser_buffer).unwrap();
        assert_eq!(v.as_slice(), ser_buffer.as_ref());

        let v: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let de = Vec::<u8>::deserialize(DeBuffer::from(v)).unwrap();
        assert_eq!(v, de.as_slice());
    }

    #[test]
    fn test_nl_str() {
        let s = "AAAAA";
        let mut ser_buffer = SerBuffer::new(Some(s.len() + 1));
        ser_buffer = s.serialize(ser_buffer).unwrap();
        assert_eq!(&[65, 65, 65, 65, 65, 0], ser_buffer.as_ref());
    }

    #[test]
    fn test_nl_string() {
        let s = "AAAAA".to_string();
        let desired_s = "AAAAA\0";
        let mut ser_buffer = SerBuffer::new(Some(s.len() + 1));
        ser_buffer = s.serialize(ser_buffer).unwrap();
        assert_eq!(desired_s.as_bytes(), ser_buffer.as_ref());

        let s = "AAAAAA\0";
        let de_s = "AAAAAA".to_string();
        let de = String::deserialize(DeBuffer::from(s.as_bytes())).unwrap();
        assert_eq!(de_s, de)
    }
}
