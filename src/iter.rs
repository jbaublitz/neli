//! Module for iteration over netlink responses

use std::{io::Cursor, marker::PhantomData};

use log::trace;

use crate::{
    FromBytes, FromBytesWithInput, Size, consts::nl::NlType, err::SocketError, nl::Nlmsghdr,
};

/// Iterator over a single buffer received from a [`recv`][crate::socket::NlSocket::recv]
/// call.
pub struct NlBufferIter<T, P, B> {
    buffer: Cursor<B>,
    next_is_none: bool,
    data: PhantomData<(T, P)>,
}

impl<T, P, B> NlBufferIter<T, P, B>
where
    B: AsRef<[u8]>,
{
    #[cfg(any(feature = "sync", feature = "async"))]
    pub(crate) fn new(buffer: Cursor<B>) -> Self {
        NlBufferIter {
            buffer,
            next_is_none: false,
            data: PhantomData,
        }
    }

    /// Optional method for parsing messages of varied types in the same buffer. Models
    /// the [`Iterator`] API.
    pub fn next_typed<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, SocketError>>
    where
        TT: NlType,
        PP: Size + FromBytesWithInput<Input = usize>,
    {
        if self.buffer.position() as usize == self.buffer.get_ref().as_ref().len()
            || self.next_is_none
        {
            None
        } else {
            match Nlmsghdr::from_bytes(&mut self.buffer).map_err(SocketError::from) {
                Ok(msg) => {
                    trace!("Message received: {msg:?}");
                    Some(Ok(msg))
                }
                Err(e) => {
                    self.next_is_none = true;
                    Some(Err(e))
                }
            }
        }
    }
}

impl<T, P, B> Iterator for NlBufferIter<T, P, B>
where
    B: AsRef<[u8]>,
    T: NlType,
    P: Size + FromBytesWithInput<Input = usize>,
{
    type Item = Result<Nlmsghdr<T, P>, SocketError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_typed::<T, P>()
    }
}
