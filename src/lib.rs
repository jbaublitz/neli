//! # neli: Type safety for netlink
//!
//! ## Rationale
//!
//! This crate aims to be a pure Rust implementation that defines
//! the necessary constants and wraps them in enums to distinguish
//! between various categories of constants in the context of netlink.
//!
//! ## The project is broken down into the following modules:
//! * `attr` - This defines a generic interface for netlink attributes
//!   (both generic and routing netlink attributes).
//! * `consts` - This is where all of the C-defined constants are
//!   wrapped into type safe enums for use in the library.
//! * `err` - This module contains all of the protocol and
//!   library-level errors encountered in the code.
//! * `genl` - This code provides parsing for the generic netlink
//! * `iter` - This code handles iterating over received netlink
//!   packets.
//! * `nl` - This is the top level netlink header code that handles
//!   the header that all netlink messages are encapsulated in.
//! * `router` - High level API handling ACK and PID validation as well as automatic
//!   sequence number handling.
//! * `rtnl` - Routing netlink subsystem of the netlink protocol.
//! * `socket` - Lower level API for use in sending and receiving messages.
//! * `types` - Wrapper data types used in the library primarily to represent parts
//!   of netlink messages.
//! * `utils` - Data structures used for FFI and synchronization in socket operations.
//!
//! ## Design decisions
//!
//! This library has a range of APIs. Some APIs like [`NlSocket`][crate::socket::NlSocket]
//! are basically just wrappers for syscalls, while higher level APIs like
//! [`NlRouter`][crate::router::synchronous::NlRouter] provide features like ACK
//! validation, socket PID validation, and sequence number handling.
//!
//! The goal of this library is completeness for handling netlink and
//! am working to incorporate features that will make this library
//! easier to use in all use cases. If you have a use case you
//! would like to see supported, please open an issue on Github.
//!
//! ## Examples
//!
//! Examples of working code exist in the `examples/` subdirectory on
//! Github. Run `cargo build --examples` to build the examples.
//!
//! Workflows usually follow a pattern of socket creation, and
//! then either sending and receiving messages in request/response
//! formats:
//!
//! ```
//! use std::error::Error;
//!
//! use neli::{
//!     consts::{genl::*, nl::*, socket::*},
//!     err::RouterError,
//!     genl::{Genlmsghdr, GenlmsghdrBuilder, Nlattr},
//!     nl::{NlmsghdrBuilder, NlPayload},
//!     router::synchronous::NlRouter,
//!     types::{Buffer, GenlBuffer},
//!     utils::Groups,
//! };
//!
//! const GENL_VERSION: u8 = 1;
//!
//! fn request_response() -> Result<(), Box<dyn Error>> {
//!     let (socket, _) = NlRouter::connect(
//!         NlFamily::Generic,
//!         None,
//!         Groups::empty(),
//!     )?;
//!
//!     let recv = socket.send::<_, _, NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(
//!         GenlId::Ctrl,
//!         NlmF::DUMP,
//!         NlPayload::Payload(
//!             GenlmsghdrBuilder::<_, CtrlAttr, _>::default()
//!                 .cmd(CtrlCmd::Getfamily)
//!                 .version(GENL_VERSION)
//!                 .build()?
//!         ),
//!     )?;
//!
//!     for msg in recv {
//!         let msg = msg?;
//!         // Do things with response here...
//!     }
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
//!     consts::{genl::*, nl::*, socket::*},
//!     err::RouterError,
//!     genl::Genlmsghdr,
//!     router::synchronous::NlRouter,
//!     utils::Groups,
//! };
//!
//! fn subscribe_to_mcast() -> Result<(), Box<dyn Error>> {
//!     let (s, multicast) = NlRouter::connect(
//!         NlFamily::Generic,
//!         None,
//!         Groups::empty(),
//!     )?;
//!     let id = s.resolve_nl_mcast_group(
//!         "my_family_name",
//!         "my_multicast_group_name",
//!     )?;
//!     s.add_mcast_membership(Groups::new_groups(&[id]))?;
//!     for next in multicast {
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

pub mod attr;
pub mod connector;
pub mod consts;
pub mod err;
pub mod genl;
pub mod iter;
pub mod nl;
pub mod router;
pub mod rtnl;
pub mod socket;
pub mod types;
pub mod utils;

use std::{
    fmt::Debug,
    io::{Cursor, Read, Write},
    marker::PhantomData,
    str,
};

use byteorder::{BigEndian, NativeEndian, ReadBytesExt};
pub use neli_proc_macros::{FromBytes, FromBytesWithInput, Header, Size, ToBytes, neli_enum};

use crate::{
    self as neli,
    consts::alignto,
    err::{DeError, SerError},
};

/// A trait defining methods that apply to all netlink data
/// structures related to sizing of data types.
pub trait Size {
    /// Size of the unpadded data structure. This will usually
    /// only be unaligned for variable length types like
    /// strings or byte buffers.
    fn unpadded_size(&self) -> usize;

    /// Get the size of the payload and align it to
    /// the required netlink byte alignment.
    fn padded_size(&self) -> usize {
        alignto(self.unpadded_size())
    }
}

/// A trait defining methods that apply to constant-sized
/// data types related to size.
pub trait TypeSize {
    /// Get the size of a constant-sized data type.
    fn type_size() -> usize;
}

/// A trait defining a netlink data structure's conversion to
/// a byte buffer.
pub trait ToBytes: Debug {
    /// Takes a byte buffer and serializes the data structure into
    /// it.
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError>;

    /// Pad a netlink message to the appropriate alignment.
    fn pad(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        let num_pad_bytes = alignto(buffer.position() as usize) - buffer.position() as usize;
        buffer.write_all(&[0; libc::NLA_ALIGNTO as usize][..num_pad_bytes])?;
        Ok(())
    }
}

/// A trait defining how to convert from a byte buffer to a netlink
/// data structure.
pub trait FromBytes: Sized + Debug {
    /// Takes a byte buffer and returns the deserialized data
    /// structure.
    fn from_bytes(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError>;

    /// Strip padding from a netlink message.
    fn strip(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<(), DeError> {
        let num_strip_bytes = alignto(buffer.position() as usize) - buffer.position() as usize;
        buffer.read_exact(&mut [0; libc::NLA_ALIGNTO as usize][..num_strip_bytes])?;
        Ok(())
    }
}

/// Takes an arbitrary input which serves as additional information
/// for guiding the conversion from a byte buffer to a data
/// structure. A common workflow is a data structure that has a size
/// to determine how much more of the data in the byte buffer is
/// part of a given data structure.
pub trait FromBytesWithInput: Sized + Debug {
    /// The type of the additional input.
    type Input: Debug;

    /// Takes a byte buffer and an additional input and returns
    /// the deserialized data structure.
    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError>;

    /// Strip padding from a netlink message.
    fn strip(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<(), DeError> {
        let num_strip_bytes = alignto(buffer.position() as usize) - buffer.position() as usize;
        buffer.read_exact(&mut [0; libc::NLA_ALIGNTO as usize][..num_strip_bytes])?;
        Ok(())
    }
}

/// Takes an arbitrary input which serves as additional information
/// for guiding the conversion from a byte buffer to a data
/// structure. A common workflow is a data structure that has a size
/// to determine how much more of the data in the byte buffer is
/// part of a given data structure.
///
/// This trait borrows instead of copying.
pub trait FromBytesWithInputBorrowed<'a>: Sized + Debug {
    /// The type of the additional input.
    type Input: Debug;

    /// Takes a byte buffer and an additional input and returns
    /// the deserialized data structure.
    fn from_bytes_with_input(
        buffer: &mut Cursor<&'a [u8]>,
        input: Self::Input,
    ) -> Result<Self, DeError>;

    /// Strip padding from a netlink message.
    fn strip(buffer: &mut Cursor<&'a [u8]>) -> Result<(), DeError> {
        let num_strip_bytes = alignto(buffer.position() as usize) - buffer.position() as usize;
        buffer.read_exact(&mut [0; libc::NLA_ALIGNTO as usize][..num_strip_bytes])?;
        Ok(())
    }
}

/// Defined for data structures that contain a header.
pub trait Header {
    /// Return the size in bytes of the data structure header.
    fn header_size() -> usize;
}

macro_rules! impl_nl_int {
    (impl__ $ty:ty) => {
        impl $crate::Size for $ty {
            fn unpadded_size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }
        }

        impl $crate::TypeSize for $ty {
            fn type_size() -> usize {
                std::mem::size_of::<$ty>()
            }
        }

    };
    ($ty:ty, $read_method:ident, $write_method:ident) => {
        impl_nl_int!(impl__ $ty);

        impl $crate::ToBytes for $ty {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), $crate::err::SerError> {
                <std::io::Cursor::<Vec<u8>> as byteorder::WriteBytesExt>::$write_method(buffer, *self)?;
                Ok(())
            }
        }

        impl $crate::FromBytes for $ty {
            fn from_bytes(buffer: &mut std::io::Cursor<impl AsRef<[u8]>>) -> Result<Self, $crate::err::DeError> {
                Ok(<std::io::Cursor<_> as byteorder::ReadBytesExt>::$read_method(buffer)?)
            }
        }
    };
    ($ty:ty, $read_method:ident, $write_method:ident, $endianness:ty) => {
        impl_nl_int!(impl__ $ty);

        impl $crate::ToBytes for $ty {
            fn to_bytes(&self, buffer: &mut std::io::Cursor<Vec<u8>>) -> Result<(), $crate::err::SerError> {
                <std::io::Cursor::<Vec<u8>> as byteorder::WriteBytesExt>::$write_method::<$endianness>(buffer, *self)?;
                Ok(())
            }
        }

        impl $crate::FromBytes for $ty {
            fn from_bytes(buffer: &mut std::io::Cursor<impl AsRef<[u8]>>) -> Result<Self, $crate::err::DeError> {
                Ok(<std::io::Cursor<_> as byteorder::ReadBytesExt>::$read_method::<$endianness>(buffer)?)
            }
        }
    }
}

impl_nl_int!(u8, read_u8, write_u8);
impl_nl_int!(u16, read_u16, write_u16, NativeEndian);
impl_nl_int!(u32, read_u32, write_u32, NativeEndian);
impl_nl_int!(u64, read_u64, write_u64, NativeEndian);
impl_nl_int!(u128, read_u128, write_u128, NativeEndian);
impl_nl_int!(i8, read_i8, write_i8);
impl_nl_int!(i16, read_i16, write_i16, NativeEndian);
impl_nl_int!(i32, read_i32, write_i32, NativeEndian);
impl_nl_int!(i64, read_i64, write_i64, NativeEndian);
impl_nl_int!(i128, read_i128, write_i128, NativeEndian);
impl_nl_int!(f32, read_f32, write_f32, NativeEndian);
impl_nl_int!(f64, read_f64, write_f64, NativeEndian);

impl Size for () {
    fn unpadded_size(&self) -> usize {
        0
    }
}

impl ToBytes for () {
    fn to_bytes(&self, _: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        Ok(())
    }
}

impl FromBytes for () {
    fn from_bytes(_: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError> {
        Ok(())
    }
}

impl FromBytesWithInput for () {
    type Input = usize;

    fn from_bytes_with_input(
        _: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        assert_eq!(input, 0);
        Ok(())
    }
}

impl<T> Size for PhantomData<T> {
    fn unpadded_size(&self) -> usize {
        0
    }
}

impl<T> TypeSize for PhantomData<T> {
    fn type_size() -> usize {
        0
    }
}

impl<T> ToBytes for PhantomData<T> {
    fn to_bytes(&self, _: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        Ok(())
    }
}

impl<T> FromBytes for PhantomData<T> {
    fn from_bytes(_: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError> {
        Ok(PhantomData)
    }
}

impl Size for &'_ str {
    fn unpadded_size(&self) -> usize {
        self.len() + 1
    }
}

impl ToBytes for &'_ str {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(self.as_bytes())?;
        buffer.write_all(&[0])?;
        Ok(())
    }
}

impl<'a> FromBytesWithInputBorrowed<'a> for &'a str {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<&'a [u8]>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let slice: &[u8] = FromBytesWithInputBorrowed::from_bytes_with_input(buffer, input)?;
        let Ok(cstr) = std::ffi::CStr::from_bytes_with_nul(slice) else {
            return Err(DeError::InvalidInput(input));
        };
        Ok(cstr.to_str()?)
    }
}

impl Size for String {
    fn unpadded_size(&self) -> usize {
        self.as_str().unpadded_size()
    }
}

impl ToBytes for String {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        self.as_str().to_bytes(buffer)?;
        Ok(())
    }
}

impl FromBytesWithInput for String {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let mut buffer = Cursor::new(buffer.get_ref().as_ref());
        let s: &str = FromBytesWithInputBorrowed::from_bytes_with_input(&mut buffer, input)?;
        let s = s.to_string();
        buffer.set_position(buffer.position() + input as u64);
        Ok(s)
    }
}

impl<const N: usize> FromBytes for [u8; N] {
    fn from_bytes(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError> {
        let mut arr = [0u8; N];
        buffer.read_exact(&mut arr)?;
        Ok(arr)
    }
}

impl Size for &'_ [u8] {
    fn unpadded_size(&self) -> usize {
        self.len()
    }
}

impl<const N: usize> Size for [u8; N] {
    fn unpadded_size(&self) -> usize {
        N
    }
}

impl ToBytes for &'_ [u8] {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(self)?;
        Ok(())
    }
}

impl<const N: usize> ToBytes for [u8; N] {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(self)?;
        Ok(())
    }
}

impl<'a> FromBytesWithInputBorrowed<'a> for &'a [u8] {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<&'a [u8]>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let start = buffer.position() as usize;
        let end = start + input;
        match buffer.get_ref().get(start..end) {
            Some(buf) => Ok(buf),
            None => Err(DeError::InvalidInput(input)),
        }
    }
}

impl<T> Size for Vec<T>
where
    T: Size,
{
    fn unpadded_size(&self) -> usize {
        self.iter()
            .fold(0, |count, elem| count + elem.unpadded_size())
    }
}

impl<T> ToBytes for Vec<T>
where
    T: ToBytes,
{
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        for elem in self.iter() {
            elem.to_bytes(buffer)?;
        }
        Ok(())
    }
}

impl<T> FromBytesWithInput for Vec<T>
where
    T: FromBytes,
{
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let start = buffer.position() as usize;
        let end = start + input;

        if end > buffer.get_ref().as_ref().len() {
            return Err(DeError::InvalidInput(input));
        }

        let mut vec = Vec::new();
        while buffer.position() as usize != end {
            match T::from_bytes(buffer) {
                Ok(elem) => vec.push(elem),
                Err(e) => {
                    buffer.set_position(start as u64);
                    return Err(e);
                }
            }
            if buffer.position() as usize > end {
                buffer.set_position(start as u64);
                return Err(DeError::InvalidInput(input));
            }
        }
        Ok(vec)
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Size)]
/// A `u64` data type that will always be serialized as big endian
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

impl ToBytes for BeU64 {
    fn to_bytes(&self, buffer: &mut Cursor<Vec<u8>>) -> Result<(), SerError> {
        buffer.write_all(&self.0.to_be_bytes())?;
        Ok(())
    }
}

impl FromBytes for BeU64 {
    fn from_bytes(buffer: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, DeError> {
        Ok(BeU64(buffer.read_u64::<BigEndian>()?))
    }
}

#[cfg(test)]
fn serialize<T>(t: &T) -> Result<Vec<u8>, SerError>
where
    T: ToBytes,
{
    let mut buffer = Cursor::new(Vec::new());
    t.to_bytes(&mut buffer)?;
    Ok(buffer.into_inner())
}

#[cfg(test)]
mod test {
    use super::*;

    use env_logger::init;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref LOGGER: () = init();
    }

    #[allow(clippy::no_effect)]
    pub fn setup() {
        *LOGGER;
    }

    #[test]
    fn test_nl_u8() {
        setup();

        let v = 5u8;
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice()[0], v);

        let de = u8::from_bytes(&mut Cursor::new(&[5u8] as &[u8])).unwrap();
        assert_eq!(de, 5)
    }

    #[test]
    fn test_nl_u16() {
        setup();

        let v = 6000u16;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u16::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 6000);
    }

    #[test]
    fn test_nl_i32() {
        setup();

        let v = 600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = i32::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 600_000);

        let v = -600_000i32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = i32::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, -600_000)
    }

    #[test]
    fn test_nl_u32() {
        setup();

        let v = 600_000u32;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u32::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 600_000)
    }

    #[test]
    fn test_nl_u64() {
        setup();

        let v = 12_345_678_901_234u64;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u64::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 12_345_678_901_234);
    }

    #[test]
    fn test_nl_u128() {
        setup();

        let v = 123_456_789_012_345_678_901_234_567_890_123_456_789u128;
        let desired_buffer = v.to_ne_bytes();
        let ser_buffer = serialize(&v).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = u128::from_bytes(&mut Cursor::new(&v.to_ne_bytes() as &[u8])).unwrap();
        assert_eq!(de, 123_456_789_012_345_678_901_234_567_890_123_456_789);
    }

    #[test]
    fn test_nl_be_u64() {
        setup();

        let v = 571_987_654u64;
        let desired_buffer = v.to_be_bytes();
        let ser_buffer = serialize(&BeU64(v)).unwrap();
        assert_eq!(ser_buffer.as_slice(), &desired_buffer);

        let de = BeU64::from_bytes(&mut Cursor::new(&v.to_be_bytes() as &[u8])).unwrap();
        assert_eq!(de, BeU64(571_987_654));
    }

    #[test]
    fn test_nl_vec() {
        setup();

        let vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ser_buffer = serialize(&vec).unwrap();
        assert_eq!(vec.as_slice(), ser_buffer.as_slice());

        let v: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let de = Vec::<u8>::from_bytes_with_input(&mut Cursor::new(v), 9).unwrap();
        assert_eq!(vec, de.as_slice());
    }

    #[test]
    fn test_nl_vec_of_arrays() {
        setup();

        let vec = vec![[1, 2, 3], [4, 5, 6], [7, 8, 9]];
        let desired_vec = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ser_buffer = serialize(&vec).unwrap();
        assert_eq!(desired_vec, ser_buffer.as_slice());

        let de = Vec::<[u8; 3]>::from_bytes_with_input(&mut Cursor::new(desired_vec), 9).unwrap();
        assert_eq!(vec, de);
    }

    #[test]
    fn test_nl_slice() {
        setup();

        let slice = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let ser_buffer = serialize(slice).unwrap();
        assert_eq!(slice, ser_buffer.as_slice());

        let de: &[u8] =
            FromBytesWithInputBorrowed::from_bytes_with_input(&mut Cursor::new(slice), 9).unwrap();
        assert_eq!(slice, de);
    }

    #[test]
    fn test_nl_string() {
        setup();

        let s = "AAAAA".to_string();
        let desired_s = "AAAAA\0";
        let ser_buffer = serialize(&s).unwrap();
        assert_eq!(desired_s.as_bytes(), ser_buffer.as_slice());

        let de_s = "AAAAA".to_string();
        let de = String::from_bytes_with_input(&mut Cursor::new(desired_s.as_bytes()), 6).unwrap();
        assert_eq!(de_s, de)
    }

    #[test]
    fn test_nl_str() {
        setup();

        let s = "AAAAA";
        let desired_s = "AAAAA\0";
        let ser_buffer = serialize(&s).unwrap();
        assert_eq!(desired_s.as_bytes(), ser_buffer.as_slice());

        let de_s = "AAAAA";
        let de: &str = FromBytesWithInputBorrowed::from_bytes_with_input(
            &mut Cursor::new(desired_s.as_bytes()),
            6,
        )
        .unwrap();
        assert_eq!(de_s, de)
    }
}
