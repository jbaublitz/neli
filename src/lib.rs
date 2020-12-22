//! # Type safety for the weary netlink user
//!
//! ## Rationale
//!
//! This crate aims to be a pure Rust implementation that defines
//! the necessary constants and wraps them in enums to distinguish
//! between various categories of constants in the context of netlink.
//!
//! ## The project is broken down into the following modules:
//! * `attr` - This defines a generic interface for netlink attributes
//! (both generic and routing netlink attributes).
//! * `consts` - This is where all of the C-defined constants are
//! wrapped into type safe enums for use in the library.
//! * `err` - This module contains all of the protocol and
//! library-level errors encountered in the code.
//! * `genl` - This code provides parsing for the generic netlink
//! subsystem of the netlink protocol.
//! * `nl` - This is the top level netlink header code that handles
//! the header that all netlink messages are encapsulated in.
//! * `rtnl` - This module is for the routing netlink subsystem of the
//! netlink protocol.
//! * `socket` - This provides a socket structure for use in sending
//! and receiving messages and a number of convenience functions for
//! commonly encountered use cases.
//!
//! ## [`Nl`] trait
//!
//! `lib.rs` at the top level contains the [`Nl`] trait which
//! provides buffer size calculation functions, a serialization
//! method, and a deserialization method. It also contains
//! implementations of [`Nl`] for common types.
//!
//! ## Design decisions
//!
//! This is a fairly low level library that currently does not have a
//! whole lot of higher level handle-type data structures and
//! relies mostly on the [`NlSocket`][crate::socket::NlSocket] and
//! [`NlSocketHandle`][crate::socket::NlSocketHandle] structs
//! to provide most of the convenience functions. I hope to add a
//! higher level API sometime in the `v0.5.x` releases to ease some of
//! the workflows that have been brought to my attention.
//!
//! The goal of this library is completeness for handling netlink and
//! am working to incorporate features that will make this library
//! easier to use in all use cases. If you have a use case you
//! would like to see supported, please open an issue on Github.
//!
//! ## Examples
//!
//! Examples of working code exist in the `examples/` subdirectory on
//! Github. They have a separate `Cargo.toml` file to provide easy
//! testing and use.  
//!
//! Workflows seem to usually follow a pattern of socket creation,and
//! then either sending and receiving messages in request/response
//! formats:
//!
//! ```
//! use neli::{
//!     consts::{genl::*, nl::*, socket::*},
//!     err::NlError,
//!     genl::{Genlmsghdr, Nlattr},
//!     nl::{Nlmsghdr, NlPayload},
//!     socket::NlSocketHandle,
//!     types::{Buffer, GenlBuffer},
//!     utils::U32Bitmask,
//! };
//!
//! const GENL_VERSION: u8 = 1;
//!
//! fn request_response() -> Result<(), NlError> {
//!     let mut socket = NlSocketHandle::connect(
//!         NlFamily::Generic,
//!         None,
//!         U32Bitmask::empty(),
//!     )?;
//!
//!     let attrs: GenlBuffer<Index, Buffer> = GenlBuffer::new();
//!     let genlhdr = Genlmsghdr::new(
//!         CtrlCmd::Getfamily,
//!         GENL_VERSION,
//!         attrs,
//!     );
//!     let nlhdr = {
//!         let len = None;
//!         let nl_type = GenlId::Ctrl;
//!         let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
//!         let seq = None;
//!         let pid = None;
//!         let payload = NlPayload::Payload(genlhdr);
//!         Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
//!     };
//!     socket.send(nlhdr)?;
//!     
//!     // Do things with multi-message response to request...
//!     let mut iter = socket.iter::<Genlmsghdr<CtrlCmd, CtrlAttr>>(false);
//!     while let Some(Ok(response)) = iter.next() {
//!         // Do things with response here...
//!     }
//!     
//!     // Or get single message back...
//!     let msg = socket.recv::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! or a subscriptions to a stream of event notifications from netlink:
//!
//! ```
//! use std::error::Error;
//!
//! use neli::{
//!     consts::{genl::*, socket::*},
//!     err::NlError,
//!     genl::Genlmsghdr,
//!     socket,
//!     utils::{U32BitFlag, U32Bitmask},
//! };
//!
//! fn subscribe_to_mcast() -> Result<(), Box<dyn Error>> {
//!     let mut s = socket::NlSocketHandle::connect(
//!         NlFamily::Generic,
//!         None,
//!         U32Bitmask::empty(),
//!     )?;
//!     let id = s.resolve_nl_mcast_group(
//!         "my_family_name",
//!         "my_multicast_group_name",
//!     )?;
//!     s.add_mcast_membership(U32Bitmask::from(U32BitFlag::new(id)?))?;
//!     for next in s.iter::<Genlmsghdr<u8, u16>>(true) {
//!         // Do stuff here with parsed packets...
//!     
//!         // like printing a debug representation of them:
//!         println!("{:?}", next?);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Documentation
//!
//! Each module has been documented extensively to provide information
//! on how to use the code contained in the module. Pull requests for
//! documentation mistakes, updates, and rewording for clarity is a
//! valuable contribution as this project aims to be as simple to use
//! as possible.

#![deny(missing_docs)]

#[macro_use]
mod macros;

pub mod attr;
pub mod consts;
pub mod err;
pub mod genl;
pub mod iter;
mod neli_constants;
pub mod nl;
mod parse;
pub mod rtnl;
pub mod socket;
pub mod types;
pub mod utils;

use std::{io::Write, mem, str};

use byteorder::ByteOrder;
#[cfg(feature = "logging")]
use lazy_static::lazy_static;
#[cfg(feature = "logging")]
use log::LevelFilter;
#[cfg(feature = "logging")]
use simple_logger::SimpleLogger;

pub use crate::neli_constants::MAX_NL_LENGTH;
use crate::{
    consts::alignto,
    err::{DeError, SerError, WrappedError},
    types::{Buffer, DeBuffer, SerBuffer},
};

#[cfg(feature = "logging")]
lazy_static! {
    static ref LOGGING_INITIALIZED: bool = SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .is_ok();
    static ref SHOW_LOGS: bool = std::env::var("NELI_LOG").is_ok();
}

/// Logging mechanism for neli for debugging
#[cfg(feature = "logging")]
#[macro_export]
macro_rules! log {
    ($fmt:tt, $($args:expr),* $(,)?) => {
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
    fn serialize(&self, m: SerBuffer) -> Result<(), SerError>;

    /// Deserialization method
    fn deserialize(m: DeBuffer) -> Result<Self, DeError>;

    /// The size of the binary representation of a type not aligned
    /// to 4-byte boundary size
    fn type_size() -> Option<usize>;

    /// The size of the binary representation of a type not aligned
    /// to 4-byte boundary size
    fn type_asize() -> Option<usize> {
        Self::type_size().map(alignto)
    }

    /// The size of the binary representation of an existing value
    /// not aligned to 4-byte boundary size
    fn size(&self) -> usize;

    /// The size of the binary representation of an existing value
    /// aligned to 4-byte boundary size
    fn asize(&self) -> usize {
        alignto(self.size())
    }

    /// Pad the data serialized data structure to alignment
    fn pad(&self, mem: SerBuffer) -> Result<(), SerError> {
        let padding_len = self.asize() - self.size();
        if let Err(e) = mem
            .as_mut()
            .write_all(&[0; libc::NLA_ALIGNTO as usize][..padding_len])
        {
            Err(SerError::Wrapped(WrappedError::IOError(e)))
        } else {
            Ok(())
        }
    }
}

impl Nl for u8 {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let size = self.size();
        match mem.len() {
            i if i < size => return Err(SerError::UnexpectedEOB),
            i if i > size => return Err(SerError::BufferNotFilled),
            _ => (),
        };
        let _ = mem.as_mut().write(&[*self]);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let size = Self::type_size().expect("Integers have static size");
        match mem.len() {
            i if i < size => return Err(DeError::IncompleteType(stringify!(u8), None)),
            i if i > size => return Err(DeError::DataLeftInBuffer(stringify!(u8), None)),
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        put_int!(*self, mem, write_u16);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u16, u16))
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u16>())
    }
}

impl Nl for u32 {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        put_int!(*self, mem, write_u32);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u32, u32))
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<u32>())
    }
}

impl Nl for i32 {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        put_int!(*self, mem, write_i32);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_i32, i32))
    }

    fn size(&self) -> usize {
        mem::size_of::<i32>()
    }

    fn type_size() -> Option<usize> {
        Some(mem::size_of::<i32>())
    }
}

impl Nl for u64 {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        put_int!(*self, mem, write_u64);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(get_int!(mem, read_u64, u64))
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        put_int!(self.0, mem, write_u64, byteorder::BE);
        Ok(())
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(BeU64(get_int!(mem, read_u64, byteorder::BE, BeU64)))
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn type_size() -> Option<usize> {
        u64::type_size()
    }
}

impl<'a> Nl for &'a [u8] {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let size = self.size();
        match mem.len() {
            i if i > size => return Err(SerError::BufferNotFilled),
            i if i < size => return Err(SerError::UnexpectedEOB),
            _ => (),
        };
        if let Err(e) = mem.as_mut().write_all(self) {
            Err(SerError::Wrapped(WrappedError::from(e)))
        } else {
            Ok(())
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        if let Err(e) = mem.as_mut().write(self.as_ref()) {
            Err(SerError::Wrapped(WrappedError::from(e)))
        } else {
            Ok(())
        }
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        Ok(Buffer::from(mem))
    }

    fn type_size() -> Option<usize> {
        None
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for Vec<u8> {
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        let size = self.size();
        match mem.len() {
            i if i > size => return Err(SerError::BufferNotFilled),
            i if i < size => return Err(SerError::UnexpectedEOB),
            _ => (),
        }
        match mem.as_mut().write(self.as_bytes()) {
            Ok(write_size) => {
                assert_eq!(write_size + 1, size);
                mem[write_size] = 0;
                Ok(())
            }
            Err(e) => Err(SerError::Wrapped(WrappedError::IOError(e))),
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
    fn serialize(&self, mem: SerBuffer) -> Result<(), SerError> {
        self.as_str().serialize(mem)
    }

    fn deserialize(mem: DeBuffer) -> Result<Self, DeError> {
        let last_elem = mem.len() - 1;
        match mem.as_ref().get(last_elem) {
            Some(0) => (),
            _ => return Err(DeError::NullError),
        };
        String::from_utf8((mem[..last_elem]).to_vec()).map_err(DeError::new)
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

    use crate::utils::serialize;

    #[test]
    fn test_nl_u8() {
        let v = 5u8;
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice()[0], v);

        let s = &[5u8] as &[u8];
        let de = u8::deserialize(s).unwrap();
        assert_eq!(de, 5)
    }

    #[test]
    fn test_nl_u16() {
        let v = 6000u16;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u16::deserialize(&v.to_ne_bytes() as &[u8]).unwrap();
        assert_eq!(de, 6000);
    }

    #[test]
    fn test_nl_i32() {
        let v = 600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = i32::deserialize(&v.to_ne_bytes() as &[u8]).unwrap();
        assert_eq!(de, 600_000);

        let v = -600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = i32::deserialize(&v.to_ne_bytes() as &[u8]).unwrap();
        assert_eq!(de, -600_000)
    }

    #[test]
    fn test_nl_u32() {
        let v = 600_000u32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u32::deserialize(&v.to_ne_bytes() as &[u8]).unwrap();
        assert_eq!(de, 600_000)
    }

    #[test]
    fn test_nl_u64() {
        let v = 12_345_678_901_234u64;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u64::deserialize(&v.to_ne_bytes() as &[u8]).unwrap();
        assert_eq!(de, 12_345_678_901_234);
    }

    #[test]
    fn test_nl_be_u64() {
        let v = 571_987_654u64;
        let desired_buffer = v.to_be_bytes();
        let ser_buffer = serialize(&BeU64(v), false).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);
    }

    #[test]
    fn test_nl_slice() {
        let v: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(v, ser_buffer.as_slice());
    }

    #[test]
    fn test_nl_vec() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ser_buffer = serialize(&v, false).unwrap();
        assert_eq!(v.as_slice(), ser_buffer.as_slice());

        let v: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let de = Vec::<u8>::deserialize(v).unwrap();
        assert_eq!(v, de.as_slice());
    }

    #[test]
    fn test_nl_str() {
        let s = "AAAAA";
        let ser_buffer = serialize(&s, false).unwrap();
        assert_eq!(&[65, 65, 65, 65, 65, 0], ser_buffer.as_slice());
    }

    #[test]
    fn test_nl_string() {
        let s = "AAAAA".to_string();
        let desired_s = "AAAAA\0";
        let ser_buffer = serialize(&s, false).unwrap();
        assert_eq!(desired_s.as_bytes(), ser_buffer.as_slice());

        let s = "AAAAAA\0";
        let de_s = "AAAAAA".to_string();
        let de = String::deserialize(s.as_bytes()).unwrap();
        assert_eq!(de_s, de)
    }
}
