//! # Type safety for the weary netlink user
//! 
//! ## Rationale
//! 
//! The `libc` crate currently provides an interface for sockets but
//! the constants to configure the socket to do anything useful in netlink
//! are not included in the crate because they live in `/usr/include/linux/netlink.h` and friends.
//! As a result, doing anything with netlink in Rust is currently a bit of a headache.
//! 
//! This crate aims to define the necessary constants and wrap them in types to both take
//! advantage of the Rust type system and also avoid the need to pop open `.h` files
//! to find the information necessary to construct netlink messages.
//! 
//! ## Notes
//! 
//! This crate is currently under heavy development.
//! 
//! The `cc` crate is a build dependency to provide as much of a natively cross distribution
//! approach as possible regarding `#define`s in C. It is used to compile a C file that includes
//! the appropriate headers and exports them to the corresponding `stdint.h` types in C.

#![deny(missing_docs)]

extern crate libc;
extern crate byteorder;

/// C constants defined as types
pub mod ffi;
/// Wrapper for `libc` sockets
pub mod socket;
/// Top-level netlink header
pub mod nlhdr;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genlhdr;
/// Error module
pub mod err;

use std::ffi::CString;
use std::io::{self,Cursor,Read,Write};
use std::mem;

use byteorder::{NativeEndian,ReadBytesExt,WriteBytesExt};

use ffi::alignto;
use err::{SerError,DeError};

/// Max supported message length for netlink messages supported by the kernel
pub const MAX_NL_LENGTH: usize = 32768;

/// Enum representing stack or heap allocated memory for reading
pub enum MemRead<'a> {
    /// Buffer for deserialization on stack
    Slice(Cursor<&'a [u8]>),
    /// Buffer for unsized deserialization on heap
    Vec(Cursor<Vec<u8>>),
    /// Reference to sized buffer for deserialization on heap
    BoxedSlice(Cursor<Box<[u8]>>),
}

impl<'a> MemRead<'a> {
    /// Create new stack allocated buffer for reading
    pub fn new_slice(mem: &'a [u8]) -> Self {
        MemRead::Slice(Cursor::new(mem))
    }

    /// Create new heap allocated buffer for reading
    pub fn new_vec(mem: Vec<u8>) -> Self {
        MemRead::Vec(Cursor::new(mem))
    }

    /// Create new sized heap allocated buffer for reading
    pub fn new_boxed_slice(mem: Box<[u8]>) -> Self {
        MemRead::BoxedSlice(Cursor::new(mem))
    }

    /// Get underlying buffer as slice
    pub fn as_slice<'b>(&'b self) -> &'b [u8] {
        match *self {
            MemRead::Slice(ref cur) => cur.get_ref(),
            MemRead::Vec(ref cur) => cur.get_ref().as_slice(),
            MemRead::BoxedSlice(ref cur) => cur.get_ref().as_ref(),
        }
    }

    /// Get length of the underlying buffer
    pub fn len(&self) -> usize {
        match *self {
            MemRead::Slice(ref cur) => cur.get_ref().len(),
            MemRead::Vec(ref cur) => cur.get_ref().len(),
            MemRead::BoxedSlice(ref cur) => cur.get_ref().len(),
        }
    }
}

impl<'a> Read for MemRead<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            MemRead::Slice(ref mut cur) => cur.read(buf),
            MemRead::Vec(ref mut cur) => cur.read(buf),
            MemRead::BoxedSlice(ref mut cur) => cur.read(buf),
        }
    }
}

impl<'a> From<MemWrite<'a>> for MemRead<'a> {
    fn from(v: MemWrite<'a>) -> Self {
        match v {
            MemWrite::Slice(cur) => MemRead::Slice(Cursor::new(&*cur.into_inner())),
            MemWrite::Vec(mut cur) => {
                cur.set_position(0);
                MemRead::Vec(cur)
            },
            MemWrite::BoxedSlice(mut cur) => {
                cur.set_position(0);
                MemRead::BoxedSlice(cur)
            },
        }
    }
}

/// Enum representing stack or heap allocated memory for writing
pub enum MemWrite<'a> {
    /// Buffer for serialization on stack
    Slice(Cursor<&'a mut [u8]>),
    /// Reference to buffer for serialization on heap
    Vec(Cursor<Vec<u8>>),
    /// Reference to sized buffer for serialization on heap
    BoxedSlice(Cursor<Box<[u8]>>),
}

impl<'a> MemWrite<'a> {
    /// Create new stack allocated buffer for writing
    pub fn new_slice(mem: &'a mut [u8]) -> Self {
        MemWrite::Slice(Cursor::new(mem))
    }

    /// Create new heap allocated buffer for writing 
    pub fn new_vec(alloc_size: Option<usize>) -> Self {
        MemWrite::Vec(Cursor::new(match alloc_size {
            Some(sz) => vec![0; sz],
            None => Vec::new(),
        }))
    }

    /// Create new heap allocated buffer for writing 
    pub fn new_boxed_slice(mem: Box<[u8]>) -> Self {
        MemWrite::BoxedSlice(Cursor::new(mem))
    }

    /// Get underlying buffer as slice
    pub fn as_slice<'b>(&'b self) -> &'b [u8] {
        match *self {
            MemWrite::Slice(ref cur) => cur.get_ref(),
            MemWrite::Vec(ref cur) => cur.get_ref().as_slice(),
            MemWrite::BoxedSlice(ref cur) => cur.get_ref().as_ref(),
        }
    }

    /// Get underlying buffer as mutable slice
    pub fn as_mut_slice<'b>(&'b mut self) -> &'b mut [u8] {
        match *self {
            MemWrite::Slice(ref mut cur) => cur.get_mut(),
            MemWrite::Vec(ref mut cur) => cur.get_mut().as_mut_slice(),
            MemWrite::BoxedSlice(ref mut cur) => cur.get_mut().as_mut(),
        }
    }

    /// Get length of underlying buffer
    pub fn len(&self) -> usize {
        match *self {
            MemWrite::Slice(ref cur) => cur.get_ref().len(),
            MemWrite::Vec(ref cur) => cur.get_ref().len(),
            MemWrite::BoxedSlice(ref cur) => cur.get_ref().len(),
        }
    }
}

impl<'a> Write for MemWrite<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            MemWrite::Slice(ref mut cur) => cur.write(buf),
            MemWrite::Vec(ref mut cur) => cur.write(buf),
            MemWrite::BoxedSlice(ref mut cur) => cur.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Trait defining basic actions required for netlink communication
pub trait Nl: Sized {
    /// Serialization input type for stateful serialization - set to `()` for stateless
    /// serialization
    type SerIn;
    /// Deserialization input type for stateful deserialization - set to `()` for stateless
    /// deserialization
    type DeIn;

    /// Serialization method
    fn serialize(&self, _m: &mut MemWrite) -> Result<(), SerError> {
        unimplemented!()
    }
    /// Serialization method
    fn serialize_with(&self, _m: &mut MemWrite, _in: Self::SerIn) -> Result<(), SerError> {
        unimplemented!()
    }
    /// Stateless deserialization method
    fn deserialize(_m: &mut MemRead) -> Result<Self, DeError> {
        unimplemented!()
    }
    /// Stateful deserialization method
    fn deserialize_with(_m: &mut MemRead, _in: Self::DeIn) -> Result<Self, DeError> {
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

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        mem.write_u8(*self)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        Ok(mem.read_u8()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl Nl for u16 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        mem.write_u16::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        Ok(mem.read_u16::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for u32 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        mem.write_u32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        Ok(mem.read_u32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }
}

impl Nl for i32 {
    type SerIn = ();
    type DeIn = ();

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        mem.write_i32::<NativeEndian>(*self)?;
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        Ok(mem.read_i32::<NativeEndian>()?)
    }

    fn size(&self) -> usize {
        mem::size_of::<i32>()
    }
}

impl<'a> Nl for &'a [u8] {
    type SerIn = ();
    type DeIn = &'a mut [u8];

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        let num_bytes = mem.write(self)?;
        if alignto(self.len()) - num_bytes > 0 {
            let padding = vec![0; self.len() - num_bytes];
            mem.write(&padding)?;
        }
        Ok(())
    }

    fn deserialize_with(mem: &mut MemRead, input: &'a mut [u8]) -> Result<Self, DeError> {
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

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        let _ = mem.write(&self)?;
        Ok(())
    }

    fn serialize_with(&self, mem: &mut MemWrite, input: usize) -> Result<(), SerError> {
        let bytes: Vec<u8> = self.iter().take(input).map(|u| *u).collect();
        let num_bytes = mem.write(&bytes)?;
        if input - num_bytes > 0 {
            mem.write(&vec![0; input - num_bytes])?;
        }
        Ok(())
    }

    fn deserialize(mem: &mut MemRead) -> Result<Self, DeError> {
        let mut v = Vec::new();
        let _ = mem.read_to_end(&mut v)?;
        Ok(v)
    }

    fn deserialize_with(mem: &mut MemRead, input: usize) -> Result<Self, DeError> {
        let mut v = vec![0; input];
        let _ = mem.read(v.as_mut_slice())?;
        Ok(v)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for String {
    type SerIn = usize;
    type DeIn = usize;

    fn serialize(&self, mem: &mut MemWrite) -> Result<(), SerError> {
        let c_str = try!(CString::new(self.as_bytes()).map_err(|_| {
            SerError::new("Unable to serialize string containing null byte")
        }));
        let bytes = c_str.as_bytes_with_nul();
        let _ = mem.write(bytes)?;
        Ok(())
    }

    fn serialize_with(&self, mem: &mut MemWrite, input: usize) -> Result<(), SerError> {
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

    fn deserialize_with(mem: &mut MemRead, input: usize) -> Result<Self, DeError> {
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

    #[test]
    fn test_nl_u8() {
        let v: u8 = 5;
        let s: &mut [u8; 1] = &mut [0];
        {
            let mut mem = MemWrite::new_slice(s);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s[0], v);

        let mut mem = MemRead::new_slice(&[5]);
        let v = u8::deserialize(&mut mem).unwrap();
        assert_eq!(v, 5)
    }

    #[test]
    fn test_nl_u16() {
        let v: u16 = 6000;
        let s: &mut [u8] = &mut [0; 2];
        {
            let mut mem = MemWrite::new_slice(s);
            mem.write_u16::<NativeEndian>(6000).unwrap();
        }
        let s_test = &mut [0; 2];
        {
            let mut mem = MemWrite::new_slice(s_test);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s, s_test);

        let s: &mut [u8] = &mut [0; 2];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u16::<NativeEndian>(6000).unwrap();
        }
        let v = {
            let mut mem = MemRead::new_slice(s);
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
            let mut mem = MemWrite::new_slice(s_test);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(s, s_test);

        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600000).unwrap();
        }
        let v = {
            let mut mem = MemRead::new_slice(&*s);
            u32::deserialize(&mut mem).unwrap()
        };
        assert_eq!(v, 600000)
    }

    #[test]
    fn test_nl_vec() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let s = &mut [0; 9];
        {
            let mut mem = MemWrite::new_slice(s);
            v.serialize(&mut mem).unwrap();
        }
        assert_eq!(v, s.to_vec());

        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0];
        let v = {
            let mut mem = MemRead::new_slice(s);
            Vec::<u8>::deserialize_with(&mut mem, 9).unwrap()
        };
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8, 9])
    }

    #[test]
    fn test_nl_string() {
        let s = "AAAAA".to_string();
        let sl = &mut [0; 6];
        {
            let mut mem = MemWrite::new_slice(sl);
            s.serialize(&mut mem).unwrap();
        }
        assert_eq!(&[65, 65, 65, 65, 65, 0], sl);

        let s = &[65, 65, 65, 65, 65, 65, 65, 0];
        let mut mem = MemRead::new_slice(s);
        let string = String::deserialize_with(&mut mem, 8).unwrap();
        assert_eq!(string, "AAAAAAA".to_string());

        let s = &[65, 65, 65, 65, 65, 65, 0, 0];
        let mut mem = MemRead::new_slice(s);
        let string = String::deserialize_with(&mut mem, 7).unwrap();
        assert_eq!(string, "AAAAAA".to_string())
    }
}
