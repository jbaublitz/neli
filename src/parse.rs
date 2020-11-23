use std::{
    mem,
    slice::{Iter, IterMut},
};

use byteorder::{ByteOrder, NativeEndian};

use crate::{
    consts::nl::NlType,
    err::{DeError, NlError},
    nl::{NlPayload, Nlmsghdr},
    Nl,
};

/// Get the length of a netlink message from a buffer
pub fn packet_length_u16(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u16>()];
    <NativeEndian as ByteOrder>::read_u16(len_buffer) as usize
}

/// Get the length of a netlink message from a buffer
pub fn packet_length_u32(buffer: &[u8], position: usize) -> usize {
    let len_buffer = &buffer[position..position + mem::size_of::<u32>()];
    <NativeEndian as ByteOrder>::read_u32(len_buffer) as usize
}

pub fn parse_next<T, P>(
    buffer: &[u8],
    mut position: usize,
    expects_ack: bool,
) -> Result<(usize, Nlmsghdr<T, P>), NlError>
where
    T: NlType,
    P: Nl,
{
    let end = buffer.len();
    // Get the next packet length at the current position of the
    // buffer for the next read operation.
    let next_packet_len = packet_length_u32(buffer, position);
    // If the packet extends past the end of the number of bytes
    // read into the buffer, return an error; something
    // has gone wrong.
    if position + next_packet_len > end {
        return Err(NlError::new(DeError::UnexpectedEOB));
    }

    // Deserialize the next Nlmsghdr struct.
    let deserialized_packet_result =
        Nlmsghdr::<T, P>::deserialize(&buffer[position..position + next_packet_len]);

    let packet = deserialized_packet_result
        .map(|packet| {
            // If successful, forward the position of the buffer
            // for the next read.
            position += next_packet_len;

            packet
        })
        .map_err(NlError::new)?;

    if let NlPayload::Err(e) = packet.nl_payload {
        return Err(NlError::Nlmsgerr(e));
    }

    if expects_ack {
        if let NlPayload::Payload(_) = packet.nl_payload {
            return Err(NlError::NoAck);
        }
    }

    Ok((position, packet))
}

/// Handle returned for traversing nested attribute structures
pub enum AttrHandle<'a, O, I> {
    /// Owned vector
    Owned(O),
    /// Vector reference
    Borrowed(&'a [I]),
}

impl<'a, O, I> AttrHandle<'a, O, I>
where
    O: AsRef<[I]>,
{
    /// Create new `AttrHandle`
    pub fn new(owned: O) -> Self {
        AttrHandle::Owned(owned)
    }

    /// Create new borrowed `AttrHandle`
    pub fn new_borrowed(borrowed: &'a [I]) -> Self {
        AttrHandle::Borrowed(borrowed)
    }

    /// Pass back iterator over attributes
    pub fn iter(&self) -> Iter<I> {
        self.get_attrs().iter()
    }

    /// Get the underlying owned value as a reference
    pub fn get_attrs(&self) -> &[I] {
        match *self {
            AttrHandle::Owned(ref o) => o.as_ref(),
            AttrHandle::Borrowed(b) => b,
        }
    }
}

/// Handle for traversing nested attribute structures mutably
pub enum AttrHandleMut<'a, O, I> {
    /// Owned vector
    Owned(O),
    /// Vector reference
    Borrowed(&'a mut [I]),
}

impl<'a, O, I> AttrHandleMut<'a, O, I>
where
    O: AsRef<[I]> + AsMut<[I]>,
{
    /// Create new `AttrHandle`
    pub fn new(owned: O) -> Self {
        AttrHandleMut::Owned(owned)
    }

    /// Create new borrowed `AttrHandle`
    pub fn new_borrowed(borrowed: &'a mut [I]) -> Self {
        AttrHandleMut::Borrowed(borrowed)
    }

    /// Pass back iterator over attributes
    pub fn iter_mut(&mut self) -> IterMut<I> {
        self.get_mut_attrs().iter_mut()
    }

    /// Get the underlying owned value as a mutable reference or return `None`
    pub fn get_mut_attrs(&mut self) -> &mut [I] {
        match self {
            AttrHandleMut::Owned(ref mut o) => o.as_mut(),
            AttrHandleMut::Borrowed(b) => b,
        }
    }
}
