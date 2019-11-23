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

extern crate buffering;
extern crate byteorder;
#[cfg(feature = "stream")]
extern crate futures_core;
#[cfg(feature = "stream")]
extern crate futures_sink;
extern crate libc;
#[cfg(feature = "stream")]
extern crate mio;
#[cfg(feature = "stream")]
extern crate pin_project_lite;
#[cfg(feature = "stream")]
extern crate tokio;

/// C constants defined as types
pub mod consts;
/// Error module
pub mod err;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genl;
pub mod netfilter;
/// Top-level netlink header
pub mod nl;
/// Netlink attribute handler
pub mod nlattr;
/// Route netlink bindings
pub mod rtnl;
/// Wrapper for `libc` sockets
pub mod socket;

use std::ffi::CString;
use std::io::{Read, Write};
use std::mem;
use std::str;

pub use buffering::{StreamReadBuffer, StreamWriteBuffer};
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};

use consts::alignto;
use err::{DeError, SerError};

/// Max supported message length for netlink messages supported by the kernel
pub const MAX_NL_LENGTH: usize = 32768;

/// Trait defining basic actions required for netlink communication.
/// Implementations for basic and `neli`'s types are provided (see below). Create new
/// implementations if you have to work with a Netlink API that uses
/// values of more unusual types.
pub trait Nl: Sized {
    /// Serialization method
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError>;

    /// Stateless deserialization method
    fn deserialize<T>(m: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>;

    /// The size of the binary representation of a struct - not aligned to word size
    fn size(&self) -> usize;

    /// The size of the binary representation of a struct - aligned to word size
    fn asize(&self) -> usize {
        alignto(self.size())
    }

    /// Pad the data serialized data structure to alignment
    fn pad(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let padding_len = self.asize() - self.size();
        m.write_all(&[0; libc::NLA_ALIGNTO as usize][..padding_len])?;
        Ok(())
    }

    /// Strip padding from the deserialization buffer
    fn strip<T>(&self, m: &mut StreamReadBuffer<T>) -> Result<(), DeError>
    where
        T: AsRef<[u8]>,
    {
        let padding_len = self.asize() - self.size();
        if padding_len > 0 {
            m.read_exact(&mut [0; libc::NLA_ALIGNTO as usize][..padding_len])?;
        }
        Ok(())
    }
}

/// Deserialize trait that allows a buffer to be passed in so that references with appropriate
/// lifetimes can be returned
pub trait NlBuf<'a>: Sized {
    /// Deserialization method
    fn deserialize_buf<T>(m: &mut StreamReadBuffer<T>, b: &'a mut [u8]) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>;
}

impl Nl for u8 {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u8(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(mem.read_u8()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl Nl for u16 {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u16::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(mem.read_u16::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for u32 {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(mem.read_u32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }
}

impl Nl for i32 {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_i32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(mem.read_i32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<i32>()
    }
}

impl Nl for u64 {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u64::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(mem.read_u64::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u64>()
    }
}

impl<'a> Nl for &'a [u8] {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let _ = mem.write(self)?;
        Ok(())
    }

    fn deserialize<T>(_m: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        unimplemented!("Use deserialize_buf instead")
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a> NlBuf<'a> for &'a [u8] {
    fn deserialize_buf<T>(
        mem: &mut StreamReadBuffer<T>,
        input: &'a mut [u8],
    ) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        mem.read_exact(input)?;
        Ok(input)
    }
}

impl Nl for Vec<u8> {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let size_hint = mem.take_size_hint();
        let slice: &[u8] = self.as_ref();
        let slice_hinted = match size_hint {
            Some(sh) => &slice[0..sh],
            None => slice,
        };
        let _ = mem.write(slice_hinted)?;
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        let v = match mem.take_size_hint() {
            Some(sh) => {
                let mut v = vec![0; sh];
                let _ = mem.read(v.as_mut_slice())?;
                v
            }
            None => {
                let mut v = Vec::new();
                let _ = mem.read_to_end(&mut v)?;
                v
            }
        };
        Ok(v)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a> Nl for &'a str {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let str_bytes = self.as_bytes();
        let nul = &[0u8];
        let bytes = match mem.take_size_hint() {
            Some(sh) => [&str_bytes[..sh - 1], nul],
            None => [str_bytes, nul],
        };
        let _ = mem.write(bytes.concat().as_slice())?;
        Ok(())
    }

    fn deserialize<B>(_: &mut StreamReadBuffer<B>) -> Result<Self, DeError>
    where
        B: AsRef<[u8]>,
    {
        unimplemented!("Use deserialize_buf instead")
    }

    fn size(&self) -> usize {
        self.len() + 1
    }
}

impl<'a> NlBuf<'a> for &'a str {
    fn deserialize_buf<T>(
        mem: &mut StreamReadBuffer<T>,
        input: &'a mut [u8],
    ) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        mem.read_exact(input)?;
        let idx = input.iter().position(|elem| *elem == 0);
        let slice_ref = if let Some(i) = idx {
            &input[..(i as usize)]
        } else {
            input
        };
        Ok(str::from_utf8(slice_ref)?)
    }
}

impl Nl for String {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let size_hint = mem.take_size_hint().unwrap_or(0);
        let c_str = CString::new(self.as_bytes())
            .map_err(|_| SerError::new("Unable to serialize string containing null byte"))?;
        let bytes = c_str.as_bytes_with_nul();
        let num_bytes = mem.write(bytes)?;
        if size_hint > num_bytes {
            mem.write_all(&vec![0; size_hint - num_bytes])?;
        }
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
    where
        T: AsRef<[u8]>,
    {
        let size_hint = match mem.take_size_hint() {
            Some(sh) => sh,
            None => return Err(DeError::new("Size hint required to deserialize strings")),
        };
        let mut v = vec![0; size_hint];
        let _ = mem.read(v.as_mut_slice())?;
        let idx = v.iter().position(|elem| *elem == 0);
        if let Some(i) = idx {
            v.truncate(i);
        }
        Ok(String::from_utf8(v)?)
    }

    fn size(&self) -> usize {
        self.len() + 1
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Cursor;

    #[test]
    fn test_nl_u8() {
        let v: u8 = 5;
        let s: &mut [u8; 1] = &mut [0];
        {
            let mut mem = StreamWriteBuffer::new_sized(s);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s[0], v);

        let mut mem = StreamReadBuffer::new(&[5]);
        let v = u8::deserialize(&mut mem).unwrap();
        assert_eq!(v, 5)
    }

    #[test]
    fn test_nl_u16() {
        let v: u16 = 6000;
        let s: &mut [u8] = &mut [0; 2];
        {
            let mut mem = StreamWriteBuffer::new_sized(s);
            mem.write_u16::<NativeEndian>(6000).unwrap();
        }
        let s_test = &mut [0; 2];
        {
            let mut mem = StreamWriteBuffer::new_sized(s_test);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s, s_test);

        let s: &mut [u8] = &mut [0; 2];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u16::<NativeEndian>(6000).unwrap();
        }
        let v = {
            let mut mem = StreamReadBuffer::new(s);
            u16::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v, 6000)
    }

    #[test]
    fn test_nl_u32() {
        let v: u32 = 600_000;
        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600_000).unwrap();
        }
        let s_test = &mut [0; 4];
        {
            let mut mem = StreamWriteBuffer::new_sized(s_test);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s, s_test);

        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600_000).unwrap();
        }
        let v = {
            let mut mem = StreamReadBuffer::new(&*s);
            u32::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v, 600_000)
    }

    #[test]
    fn test_nl_u64() {
        let test_int: u64 = 12_345_678_901_234;
        let expected_serial: &mut [u8] = &mut [0; 8];
        {
            let mut c = Cursor::new(&mut *expected_serial);
            c.write_u64::<NativeEndian>(test_int).unwrap();
        }
        let test_serial = &mut [0; 8];
        {
            let mut mem = StreamWriteBuffer::new_sized(test_serial);
            test_int.serialize(&mut mem).unwrap();
        }
        assert_eq!(expected_serial, test_serial);

        let buffer: &mut [u8] = &mut [0; 8];
        {
            let mut c = Cursor::new(&mut *buffer);
            c.write_u64::<NativeEndian>(test_int).unwrap();
        }
        let deserialed_int = {
            let mut mem = StreamReadBuffer::new(&*buffer);
            u64::deserialize(&mut mem).unwrap()
        };
        assert_eq!(test_int, deserialed_int);
    }

    #[test]
    fn test_nl_vec() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let s = &mut [0; 9];
        {
            let mut mem = StreamWriteBuffer::new_sized(s);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(v, s.to_vec());

        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0];
        let mut mem = StreamReadBuffer::new(s);
        let v = {
            mem.set_size_hint(8);
            Vec::<u8>::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        let v = { Vec::<u8>::deserialize(&mut mem).unwrap() };
        assert_eq!(v.as_slice(), &[9, 0, 0, 0])
    }

    #[test]
    fn test_nl_str() {
        let s = "AAAAA";
        let sl = &mut [0; 6];
        {
            let mut mem = StreamWriteBuffer::new_sized(sl);
            s.serialize(&mut mem).unwrap();
        }
        assert_eq!(&[65, 65, 65, 65, 65, 0], sl);

        let s = &[65, 65, 65, 65, 65, 65, 0, 0];
        let st = &mut [0; 7];
        let mut mem = StreamReadBuffer::new(s);
        mem.set_size_hint(7);
        let string = <&str>::deserialize_buf(&mut mem, st).unwrap();
        assert_eq!(string, "AAAAAA")
    }

    #[test]
    fn test_nl_slice() {
        let s = &mut [0; 6];
        let sl: &[u8] = &[0, 1, 2, 3, 4, 5];
        {
            let mut mem = StreamWriteBuffer::new_sized(s);
            sl.serialize(&mut mem).unwrap();
        }
        assert_eq!(&[0, 1, 2, 3, 4, 5], sl);

        let s = &[0, 1, 2, 3, 4, 5];
        let sl = &mut [0; 6];
        let mut mem = StreamReadBuffer::new(s);
        mem.set_size_hint(6);
        let slice = <&[u8]>::deserialize_buf(&mut mem, sl).unwrap();
        assert_eq!(slice, &[0, 1, 2, 3, 4, 5])
    }

    #[test]
    fn test_nl_string() {
        let s = "AAAAA".to_string();
        let sl = &mut [0; 6];
        {
            let mut mem = StreamWriteBuffer::new_sized(sl);
            s.serialize(&mut mem).unwrap();
        }
        assert_eq!(&[65, 65, 65, 65, 65, 0], sl);

        let s = &[65, 65, 65, 65, 65, 65, 0, 0];
        let mut mem = StreamReadBuffer::new(s);
        mem.set_size_hint(8);
        let string = String::deserialize(&mut mem).unwrap();
        assert_eq!(string, "AAAAAA".to_string())
    }
}
