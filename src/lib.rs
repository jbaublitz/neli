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

use std::io::{Cursor,Read,Write};
use std::mem;

use byteorder::{NativeEndian,ReadBytesExt,WriteBytesExt};

use ffi::alignto;
use err::{SerError,DeError};

/// Struct representing the necessary state to serialize an object
pub struct NlSerState(Cursor<Vec<u8>>, Option<usize>);

impl NlSerState {
    /// Create new serialization state object
    pub fn new() -> Self {
        NlSerState(Cursor::new(Vec::new()), None)
    }

    /// Store length of payload for later use
    pub fn set_usize(&mut self, sz: usize) {
        self.1 = Some(sz);
    }

    /// Get length of payload
    pub fn get_usize(&mut self) -> Option<usize> {
        self.1.take()
    }

    /// Get buffer with serialized representation of consumed struct
    pub fn into_inner(self) -> Vec<u8> {
        self.0.into_inner()
    }
}

/// Struct representing the necessary state to deserialize an object
pub struct NlDeState<'a>(Cursor<&'a [u8]>, Option<usize>);

impl<'a> NlDeState<'a> {
    /// Create new deserialization state object
    pub fn new(s: &'a [u8]) -> Self {
        NlDeState(Cursor::new(s), None)
    }

    /// Store length of payload for later use
    pub fn set_usize(&mut self, sz: usize) {
        self.1 = Some(sz);
    }

    /// Get length of payload
    pub fn get_usize(&mut self) -> Option<usize> {
        self.1.take()
    }
}

/// Trait defining basic actions required for netlink communication
pub trait Nl: Sized + Default {
    /// Serialization method
    fn serialize(&mut self, &mut NlSerState) -> Result<(), SerError>;
    /// Deserialization method
    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError>;
    /// The size of the binary representation of a struct - not aligned to word size
    fn size(&self) -> usize;
    /// The size of the binary representation of a struct - aligned to word size
    fn asize(&self) -> usize {
        alignto(self.size())
    }
}

impl Nl for u8 {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u8(*self));
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        Ok(try!(state.0.read_u8()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl Nl for u16 {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u16::<NativeEndian>(*self));
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        Ok(try!(state.0.read_u16::<NativeEndian>()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for u32 {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u32::<NativeEndian>(*self));
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        Ok(try!(state.0.read_u32::<NativeEndian>()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u32>()
    }
}

impl Nl for Vec<u8> {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        let len = state.get_usize().unwrap_or(self.len());
        let num_bytes = state.0.write(&self)?;
        if len - num_bytes > 0 {
            let padding = vec![0; len - num_bytes];
            state.0.write(&padding)?;
        }
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let input = state.get_usize().unwrap_or(state.0.get_ref().len());
        let mut v = vec![0; input];
        let num_bytes = state.0.by_ref().take(input as u64).read(&mut v)?;
        if input > num_bytes {
            v.truncate(num_bytes);
        }
        Ok(v)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl Nl for String {
    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        self.push('\0');
        let len = state.get_usize().unwrap_or(self.len());
        let num_bytes = state.0.write(self.as_bytes())?;
        if len - num_bytes > 0 {
            let padding = vec![0; len - num_bytes];
            state.0.write(&padding)?;
        }
        Ok(())
    }

    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        let input = state.get_usize().unwrap_or(state.0.get_ref().len());
        let mut v = vec![0; input];
        let num_bytes = state.0.by_ref().take(input as u64).read(&mut v)?;
        if input > num_bytes {
            v.truncate(num_bytes);
        }
        v = v.into_iter().filter(|b| *b != 0).collect();
        let string = String::from_utf8(v)?;
        Ok(string)
    }

    fn size(&self) -> usize {
        self.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nl_u8() {
        let mut v: u8 = 5;
        let s: &[u8; 1] = &[5];
        let mut state = NlSerState::new();
        v.serialize(&mut state).unwrap();
        assert_eq!(s, state.into_inner().as_slice());

        let s: &[u8; 1] = &[5];
        let mut state = NlDeState::new(s);
        let v = u8::deserialize(&mut state).unwrap();
        assert_eq!(v, 5)
    }

    #[test]
    fn test_nl_u16() {
        let mut v: u16 = 6000;
        let s: &mut [u8] = &mut [0; 2];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u16::<NativeEndian>(6000).unwrap();
        }
        let mut state = NlSerState::new();
        v.serialize(&mut state).unwrap();
        assert_eq!(s, state.into_inner().as_slice());

        let s: &mut [u8] = &mut [0; 2];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u16::<NativeEndian>(6000).unwrap();
        }
        let mut state = NlDeState::new(&*s);
        let v = u16::deserialize(&mut state).unwrap();
        assert_eq!(v, 6000)
    }

    #[test]
    fn test_nl_u32() {
        let mut v: u32 = 600000;
        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600000).unwrap();
        }
        let mut state = NlSerState::new();
        v.serialize(&mut state).unwrap();
        assert_eq!(s, state.into_inner().as_slice());

        let s: &mut [u8] = &mut [0; 4];
        {
            let mut c = Cursor::new(&mut *s);
            c.write_u32::<NativeEndian>(600000).unwrap();
        }
        let mut state = NlDeState::new(&*s);
        let v = u32::deserialize(&mut state).unwrap();
        assert_eq!(v, 600000)
    }

    #[test]
    fn test_nl_vec() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut state = NlSerState::new();
        v.serialize(&mut state).unwrap();
        assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8, 9], state.into_inner().as_slice());

        let s = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0];
        let mut state = NlDeState::new(s);
        state.set_usize(s.len() as usize);
        let v = Vec::<u8>::deserialize(&mut state).unwrap();
        assert_eq!(v, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0])
    }

    #[test]
    fn test_nl_string() {
        let mut s = "AAAAA".to_string();
        let mut state = NlSerState::new();
        s.serialize(&mut state).unwrap();
        assert_eq!(vec![65, 65, 65, 65, 65, 0], state.into_inner().as_slice());

        let s = &[65, 65, 65, 65, 65, 65, 65, 0, 0, 0, 0];
        let mut state = NlDeState::new(s);
        state.set_usize(s.len() as usize);
        let string = String::deserialize(&mut state).unwrap();
        assert_eq!(string, "AAAAAAA".to_string())
    }
}
