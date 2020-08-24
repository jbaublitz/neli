use std::mem;

use byteorder::{ByteOrder, NativeEndian};

use crate::{
    consts::nl::NlType,
    err::{DeError, NlError},
    nl::{NlPayload, Nlmsghdr},
    types::DeBuffer,
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
    let deserialized_packet_result = Nlmsghdr::<T, P>::deserialize(DeBuffer::from(
        &buffer[position..position + next_packet_len],
    ));

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

    // If the position has reached the end of the read bytes,
    // reset the end and position to zero to trigger a new
    // socket read on the next invocation.
    if position == end {
        position = 0;
    }
    Ok((position, packet))
}
