//! # Type safety for the weary netlink user
//! 
//! ## Rationale
//! 
//! This crate aims to be a pure Rust implementation that defines
//! the necessary constants and wraps them in enums to distinguish between various categories of
//! constants in the context of netlink.

#![deny(missing_docs)]

extern crate buffering;
extern crate byteorder;
extern crate libc;
extern crate mio;
#[cfg(feature = "stream")]
extern crate tokio;

/// C constants defined as types
pub mod consts;
/// Wrapper for `libc` sockets
pub mod socket;
/// Netlink attribute handler
pub mod nlattr;
/// Top-level netlink header
pub mod nl;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genl;
/// Route netlink bindings
pub mod rtnl;
/// Error module
pub mod err;

use std::ffi::CString;
use std::io::{Read,Write};
use std::mem;
use std::str;

pub use buffering::copy::{StreamReadBuffer,StreamWriteBuffer};
use byteorder::{NativeEndian,ReadBytesExt,WriteBytesExt};

use consts::alignto;
use err::{SerError,DeError};

/// Max supported message length for netlink messages supported by the kernel
pub const MAX_NL_LENGTH: usize = 32768;

/// Trait defining basic actions required for netlink communication.
/// Implementations for basic and `neli`'s types are provided (see below). Create new
/// implementations if you have to work with a Netlink API that uses
/// values of more unusual types.
pub trait Nl: Sized {
    /// Serialization input type for stateful serialization - set to `()` for stateless
    /// serialization
    type SerIn;
    /// Deserialization input type for stateful deserialization - set to `()` for stateless
    /// deserialization
    type DeIn;

    /// Serialization method
    fn serialize(&self, _m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        unimplemented!()
    }
    /// Serialization method
    fn serialize_with(&self, _m: &mut StreamWriteBuffer, _in: Self::SerIn) -> Result<(), SerError> {
        unimplemented!()
    }
    /// Stateless deserialization method
    fn deserialize<T>(_m: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        unimplemented!()
    }
    /// Stateful deserialization method
    fn deserialize_with<T>(_m: &mut StreamReadBuffer<T>, _in: Self::DeIn) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        unimplemented!()
    }
    /// The size of the binary representation of a struct - not aligned to word size
    fn size(&self) -> usize;
    /// The size of the binary representation of a struct - aligned to word size
    fn asize(&self) -> usize {
        alignto(self.size())
    }
}

impl Nl for u8 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u8(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        Ok(mem.read_u8()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl Nl for u16 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u16::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        Ok(mem.read_u16::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for u32 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        Ok(mem.read_u32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }
}

impl Nl for i32 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_i32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        Ok(mem.read_i32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<i32>()
    }
}

impl Nl for u64 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        mem.write_u64::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        Ok(mem.read_u64::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u64>()
    }
}

impl<'a> Nl for &'a [u8] {
    type SerIn = ();
    type DeIn = &'a mut [u8];

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let num_bytes = mem.write(self)?;
        if alignto(self.len()) - num_bytes > 0 {
            let padding = vec![0; self.len() - num_bytes];
            mem.write(&padding)?;
        }
        Ok(())
    }

    fn deserialize_with<T>(mem: &mut StreamReadBuffer<T>, input: &'a mut [u8]) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        mem.read_exact(input)?;
        Ok(input)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for Vec<u8> {
    type SerIn = usize;
    type DeIn = usize;

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let _ = mem.write(&self)?;
        Ok(())
    }

    fn serialize_with(&self, mem: &mut StreamWriteBuffer, input: usize) -> Result<(), SerError> {
        let bytes: Vec<u8> = self.iter().take(input).map(|u| *u).collect();
        let _ = mem.write(&bytes)?;
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        let mut v = Vec::new();
        let _ = mem.read_to_end(&mut v)?;
        Ok(v)
    }

    fn deserialize_with<T>(mem: &mut StreamReadBuffer<T>, input: usize) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        let mut v = vec![0; input];
        let _ = mem.read(v.as_mut_slice())?;
        Ok(v)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a> Nl for &'a str {
    type SerIn = usize;
    type DeIn = &'a mut [u8];

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let _ = mem.write(bytes)?;
        Ok(())
    }

    fn serialize_with(&self, mem: &mut StreamWriteBuffer, input: usize) -> Result<(), SerError> {
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let num_bytes = mem.write(bytes)?;
        if input - num_bytes > 0 {
            mem.write(&vec![0; input - num_bytes])?;
        }
        Ok(())
    }

    fn deserialize_with<T>(mem: &mut StreamReadBuffer<T>, input: &'a mut [u8]) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        mem.read_exact(input)?;
        let idx = input.iter().position(|elem| *elem == 0);
        let mut new_input: (&[u8], &[u8]) = (&[], &[]);
        if let Some(i) = idx {
            new_input = input.split_at(i);
        }
        let (beginning, _) = new_input;
        Ok(str::from_utf8(beginning)?)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for String {
    type SerIn = usize;
    type DeIn = usize;

    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let _ = mem.write(bytes)?;
        Ok(())
    }

    fn serialize_with(&self, mem: &mut StreamWriteBuffer, input: usize) -> Result<(), SerError> {
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let num_bytes = mem.write(bytes)?;
        if input - num_bytes > 0 {
            mem.write(&vec![0; input - num_bytes])?;
        }
        Ok(())
    }

    fn deserialize_with<T>(mem: &mut StreamReadBuffer<T>, input: usize) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        let mut v = vec![0; input];
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
        let v: u32 = 600000;
        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600000).unwrap();
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
            c.write_u32::<NativeEndian>(600000).unwrap();
        }
        let v = {
            let mut mem = StreamReadBuffer::new(&*s);
            u32::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v, 600000)
    }

    #[test]
    fn test_nl_u64() {
        let test_int: u64 = 12345678901234;
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
        let v = {
            let mut mem = StreamReadBuffer::new(s);
            Vec::<u8>::deserialize_with(&mut mem, 9).unwrap()
        };
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8, 9])
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

        let s = &[65, 65, 65, 65, 65, 65, 65, 0];
        let mut mem = StreamReadBuffer::new(s);
        let string = String::deserialize_with(&mut mem, 8).unwrap();
        assert_eq!(string, "AAAAAAA".to_string());

        let s = &[65, 65, 65, 65, 65, 65, 0, 0];
        let mut mem = StreamReadBuffer::new(s);
        let string = String::deserialize_with(&mut mem, 7).unwrap();
        assert_eq!(string, "AAAAAA".to_string())
    }
}
