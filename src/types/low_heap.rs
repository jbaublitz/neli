pub use std::vec::Vec;

use smallvec::SmallVec;

/// A buffer of bytes that, when used, can avoid unnecessary allocations.
pub type Buffer = SmallVec<[u8; 64]>;

/// A buffer to serialize into
pub type SerBuffer<'a> = &'a mut [u8];

/// A buffer to deserialize from
pub type DeBuffer<'a> = &'a [u8];

/// A buffer to hold data read from sockets
pub type SockBuffer = Box<[u8]>;

/// A buffer of netlink messages.
pub type NlBuffer<T, P> = SmallVec<[Nlmsghdr<T, P>; 8]>;

/// A buffer of generic netlink attributes.
pub type GenlBuffer<T, P> = SmallVec<[Nlattr<T, P>; 8]>;

/// A buffer of rtnetlink attributes.
pub type RtBuffer<T, P> = SmallVec<[Rtattr<T, P>; 8]>;
