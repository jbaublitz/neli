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

extern crate libc;
extern crate byteorder;

/// C constants defined as types
pub mod ffi;
/// Wrapper for `libc` sockets
//pub mod socket;
/// Top-level netlink header
pub mod nlhdr;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genlhdr;
/// Error module
pub mod err;

use std::io::{Cursor,Read,Write};
use std::mem;
use std::marker::PhantomData;

use byteorder::{NativeEndian,ReadBytesExt,WriteBytesExt};

use ffi::alignto;
use err::{SerError,DeError};

pub struct NlSerState(Cursor<Vec<u8>>);

impl NlSerState {
    pub fn new() -> Self {
        NlSerState(Cursor::new(Vec::new()))
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0.into_inner()
    }
}

pub struct NlDeState<'a>(Cursor<&'a [u8]>);

impl<'a> NlDeState<'a> {
    pub fn new(s: &'a [u8]) -> Self {
        NlDeState(Cursor::new(s))
    }
}

pub trait Nl: Sized + Default {
    type Input: Default;

    fn serialize(&mut self, &mut NlSerState) -> Result<(), SerError>;
    fn deserialize_with(&mut NlDeState, Self::Input) -> Result<Self, DeError>;
    fn deserialize(state: &mut NlDeState) -> Result<Self, DeError> {
        Self::deserialize_with(state, Self::Input::default())
    }
    fn size(&self) -> usize;
    fn asize(&self) -> usize {
        alignto(self.size())
    }
}

impl Nl for u8 {
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u8(*self));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input)
                        -> Result<Self, DeError> {
        Ok(try!(state.0.read_u8()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

impl Nl for u16 {
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u16::<NativeEndian>(*self));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input)
                        -> Result<Self, DeError> {
        Ok(try!(state.0.read_u16::<NativeEndian>()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for u32 {
    type Input = ();

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write_u32::<NativeEndian>(*self));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, _input: Self::Input)
                        -> Result<Self, DeError> {
        Ok(try!(state.0.read_u32::<NativeEndian>()))
    }

    fn size(&self) -> usize {
        mem::size_of::<u16>()
    }
}

impl Nl for Vec<u8> {
    type Input = usize;

    fn serialize(&mut self, state: &mut NlSerState) -> Result<(), SerError> {
        try!(state.0.write(self.as_slice()));
        Ok(())
    }

    fn deserialize_with(state: &mut NlDeState, input: Self::Input)
                        -> Result<Self, DeError> {
        let mut v = Vec::with_capacity(input);
        try!(state.0.read(v.as_mut_slice()));
        Ok(v)
    }

    fn size(&self) -> usize {
        self.len()
    }
}
