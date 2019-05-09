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
#[cfg(feature = "stream")]
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
    /// Serialization method
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError>;

    /// Stateless deserialization method
    fn deserialize<T>(m: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]>;

    /// The size of the binary representation of a struct - not aligned to word size
    fn size(&self) -> usize;

    /// The size of the binary representation of a struct - aligned to word size
    fn asize(&self) -> usize {
        alignto(self.size())
    }
}

/// Deserialize trait that allows a buffer to be passed in so that references with appropriate
/// lifetimes can be returned
pub trait NlBuf<'a>: Sized {
    /// Deserialization method
    fn deserialize_buf<T>(m: &mut StreamReadBuffer<T>, b: &'a mut [u8]) -> Result<Self, DeError>
            where T: AsRef<[u8]>;
}

impl Nl for u8 {
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
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let num_bytes = mem.write(self)?;
        if alignto(self.len()) - num_bytes > 0 {
            let padding = vec![0; self.len() - num_bytes];
            mem.write(&padding)?;
        }
        Ok(())
    }

    fn deserialize<T>(_m: &mut StreamReadBuffer<T>) -> Result<Self, DeError> where T: AsRef<[u8]> {
        unimplemented!()
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl<'a> NlBuf<'a> for &'a [u8] {
    fn deserialize_buf<T>(mem: &mut StreamReadBuffer<T>, input: &'a mut [u8]) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
        mem.read_exact(input)?;
        Ok(input)
    }
}

impl Nl for Vec<u8> {
    fn serialize(&self, mem: &mut StreamWriteBuffer) -> Result<(), SerError> {
        let size_hint = mem.take_size_hint();
        let slice: &[u8] = &self.as_ref();
        let slice_hinted = match size_hint {
            Some(sh) => &slice[0..sh],
            None => slice,
        };
        let _ = mem.write(slice_hinted)?;
        Ok(())
    }

    fn deserialize<B>(mem: &mut StreamReadBuffer<B>) -> Result<Self, DeError> where B: AsRef<[u8]> {
        let v = match mem.take_size_hint() {
            Some(sh) => {
                let mut v = vec![0; sh];
                let _ = mem.read(v.as_mut_slice())?;
                v
            },
            None => {
                let mut v = Vec::new();
                let _ = mem.read_to_end(&mut v)?;
                v
            },
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
            where B: AsRef<[u8]> {
        unimplemented!()
    }

    fn size(&self) -> usize {
        self.len() + 1
    }
}

impl<'a> NlBuf<'a> for &'a str {
    fn deserialize_buf<T>(mem: &mut StreamReadBuffer<T>, input: &'a mut [u8])
        -> Result<Self, DeError> where T: AsRef<[u8]> {
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
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let num_bytes = mem.write(bytes)?;
        if size_hint > num_bytes {
            mem.write(&vec![0; size_hint - num_bytes])?;
        }
        Ok(())
    }

    fn deserialize<T>(mem: &mut StreamReadBuffer<T>) -> Result<Self, DeError>
            where T: AsRef<[u8]> {
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
        let mut mem = StreamReadBuffer::new(s);
        let v = {
            mem.set_size_hint(8);
            Vec::<u8>::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        let v = {
            Vec::<u8>::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v.as_slice(), &[9, 0, 0, 0])
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
