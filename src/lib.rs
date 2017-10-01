//! # nl - Type safety for the weary netlink user
//! 
//! ## Rationale
//! 
//! The `libc` crate currently provides an interface for sockets but
//! the constants to configure the socket to do anything useful in netlink,
//! because they live in `/usr/include/linux/netlink.h` and friends,
//! are not included in the crate. As a result, doing anything with netlink in Rust
//! 
//! ## Notes
//! 
//! This crate is currently under heavy development.

extern crate libc;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate byteorder;

pub mod ffi;
pub mod socket;
pub mod nlhdr;
pub mod genlhdr;
pub mod ser;
pub mod de;
pub mod err;
