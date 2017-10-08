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
//! This is all further helped by `serde` which provides the underlying layer for byte
//! serialization and deserialization used to convert messages from native Rust data
//! structures avoiding `[#repr(C)]` to a byte slice compatible with the libc API.
//! 
//! ## Notes
//! 
//! This crate is currently under heavy development.
//! 
//! The `cc` crate is a build dependency to provide as much of a natively cross distribution
//! approach as possible regarding `#define`s in C. It is used to compile a C file that includes
//! the appropriate headers and exports them to the corresponding `stdint.h` types in C.
//! This is then linked into Rust to expose them to the `ffi.rs` module. Big thanks to the
//! `serde` people for working with me on my pull request to make this ever so much simpler
//! to implement.

extern crate libc;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate byteorder;

/// C constants defined as types
pub mod ffi;
/// Wrapper for `libc` sockets
pub mod socket;
/// Top-level netlink header
pub mod nlhdr;
/// Genetlink (generic netlink) header and attribute helpers
pub mod genlhdr;
/// `serde` serializaton implementation
pub mod ser;
/// `serde` deserializaton implementation
pub mod de;
/// Errors and conversions
pub mod err;

use ffi::alignto;

pub trait Nl {
    fn size(&self) -> usize;
    fn asize(&self) -> usize {
        alignto(self.size())
    }
}
