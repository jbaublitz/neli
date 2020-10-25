use smallvec::SmallVec;

use crate::{nl::Nlmsghdr, nlattr::Nlattr, rtnl::Rtattr, types::traits::BufferOps, MAX_NL_LENGTH};

/// A buffer of bytes that, when used, can avoid unnecessary allocations.
pub struct Buffer(SmallVec<[u8; 64]>);

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> Self {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&self) -> Self {
        self.0.as_mut_slice()
    }
}

impl BufferOps for Buffer {
    fn new() -> Self {
        Buffer(SmallVec::new())
    }

    fn from_slice(slice: &[u8]) -> Self {
        Buffer(SmallVec::from_slice(slice))
    }

    fn extend_from_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A buffer to serialize into
pub struct SerBuffer<'a>(&'a mut [u8]);

/// A buffer to deserialize from
pub struct DeBuffer<'a>(&'a [u8]);

/// A buffer to hold data read from sockets
pub struct SockBuffer(Box<[u8]>);

impl SockBufferOps for SockBuffer {
    fn new() -> Self {
        SockBuffer(Box::new([0; MAX_NL_LENGTH]))
    }

    fn get_ref(&self) -> Option<SockBufferRef> {}
}

/// A buffer of netlink messages.
pub struct NlBuffer<T, P>(SmallVec<[Nlmsghdr<T, P>; 8]>);

/// A buffer of generic netlink attributes.
pub struct GenlBuffer<T, P>(SmallVec<[Nlattr<T, P>; 8]>);

/// A buffer of rtnetlink attributes.
pub struct RtBuffer<T, P>(SmallVec<[Rtattr<T, P>; 8]>);

/// A buffer of flag constants.
pub struct FlagBuffer<T>([T; 64]);
